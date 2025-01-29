#!/bin/bash

# Prerequisite check(s) for module.
check() {

    require_binaries ip ps pstree killall sshd || return 1
    return 0

}

# Module dependency requirements.
depends() {

    echo bash
    return 0

}

install() {

    inst /bin/ip /usr/bin/ps /usr/bin/pstree /usr/bin/killall /usr/sbin/sshd
    inst_multiple ip dhclient sed awk grep pgrep tr expr
    inst_multiple -o arping arping2
    strstr "$(arping 2>&1)" "ARPing 2" && mv "$initdir/bin/arping" "$initdir/bin/arping2"
    inst_multiple -o ping ping6
    inst_hook initqueue/finished 10 "$moddir/net-sshd-standalone.sh"
    inst_hook cleanup 10 "$moddir/net-sshd-standalone-cleanup.sh"

    if [ ! -d /etc/dracut-net-sshd-standalone/keys ]; then
        mkdir -p /etc/dracut-net-sshd-standalone/etc/ssh
        ssh-keygen -A -f /etc/dracut-net-sshd-standalone/
        mkdir -p /etc/dracut-net-sshd-standalone/keys
        mv /etc/dracut-net-sshd-standalone/etc/ssh/* /etc/dracut-net-sshd-standalone/keys
        rmdir /etc/dracut-net-sshd-standalone/etc/ssh
    fi

    local key_type ssh_host_key authorized_keys authorized_keys_wc

    local found_host_key=no
    for key_type in dsa ecdsa ed25519 rsa; do
        ssh_host_key=/etc/dracut-net-sshd-standalone/keys/ssh_host_"$key_type"_key
        if [ -f "$ssh_host_key" ]; then
            inst_simple "$ssh_host_key".pub /etc/ssh/ssh_host_"$key_type"_key.pub
            /usr/bin/install -m 600 "$ssh_host_key" \
                    "$initdir/etc/ssh/ssh_host_${key_type}_key"
            found_host_key=yes
        fi
    done
    if [ "$found_host_key" = no ]; then
        dfatal "Didn't find any SSH host key!"
        return 1
    fi

    if [ -e /root/.ssh/dracut_authorized_keys ]; then
        authorized_keys=/root/.ssh/dracut_authorized_keys
    elif [ -e /etc/dracut-net-sshd-standalone/authorized_keys ]; then
        authorized_keys=/etc/dracut-net-sshd-standalone/authorized_keys
    else
        authorized_keys=/root/.ssh/authorized_keys
    fi
    if [ ! -r "$authorized_keys" ]; then
        dfatal "No authorized_keys for root user found!"
        return 1
    fi
    authorized_keys_wc=$(cat "$authorized_keys" | wc -c)
    if [ $authorized_keys_wc -eq 0 ]; then
        dfatal "Authorized keys file $authorized_keys is empty!"
        return 1
    fi

    mkdir -p -m 0700 "$initdir/root"
    mkdir -p -m 0700 "$initdir/root/.ssh"
    /usr/bin/install -m 600 "$authorized_keys" \
            "$initdir/root/.ssh/authorized_keys"

    inst_binary /usr/sbin/sshd
    inst_multiple -o /etc/sysconfig/sshd /etc/sysconfig/ssh \
            /etc/sysconfig/dracut-sshd

    # Copy ssh helper executables for OpenSSH 9.8+
    # /usr/lib/ssh          -> Arch
    # /usr/lib(64)/misc     -> Gentoo
    # /usr/libexec/openssh  -> Fedora
    # /usr/libexec/ssh      -> openSUSE
    local d
    for d in /usr/lib/ssh /usr/lib64/misc /usr/lib/misc /usr/libexec/openssh /usr/libexec/ssh ; do
        if [ -f "$d"/sshd-session ]; then
            inst_multiple "$d"/{sshd-session,sftp-server}
            break
        fi
    done

    # First entry for Fedora 28, second for Fedora 27
    inst_multiple -o /etc/crypto-policies/back-ends/opensshserver.config \
            /etc/crypto-policies/back-ends/openssh-server.config
    inst_simple "${moddir}/sshd.service" "$systemdsystemunitdir/sshd.service"
    inst_simple "${moddir}/sshd_config" /etc/ssh/sshd_config

    { grep '^sshd:' $dracutsysrootdir/etc/passwd || echo 'sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin'; } >> "$initdir/etc/passwd"
    { grep '^sshd:' $dracutsysrootdir/etc/group  || echo 'sshd:x:74:'; } >> "$initdir/etc/group"

    # Create privilege separation directory
    # /var/empty/sshd       -> Fedora, CentOS, RHEL
    # /usr/share/empty.sshd -> Fedora >= 34
    # /var/emtpy            -> Arch, OpenSSH upstream
    # /var/lib/empty        -> Suse
    # /var/chroot/ssh       -> Void Linux
    local d
    for d in /var/empty/sshd /usr/share/empty.sshd /var/empty /var/lib/empty /var/chroot/ssh ; do
        if [ -d "$d" ]; then
            mkdir -p -m 0755 "$initdir$d"
        fi
    done
    # workaround for Silverblue (in general for ostree based os)
    if grep ^OSTREE_VERSION= /etc/os-release > /dev/null; then
        mkdir -p -m 0755 "$initdir/var/empty/sshd"
    fi

    systemctl -q --root "$initdir" enable sshd

    # Add command to unlock luks volumes to bash history for easier use
    echo systemd-tty-ask-password-agent >> "$initdir/root/.bash_history"
    chmod 600 "$initdir/root/.bash_history"

    # sshd requires /var/log/lastlog for tracking login information
    mkdir -p -m 0755 "$initdir/var/log"
    touch "$initdir/var/log/lastlog"

    inst_simple "${moddir}/motd" /etc/motd
    inst_simple "${moddir}/profile" /root/.profile

    return 0

}

installkernel() {

    # Include wired net drivers, excluding wireless
    local _arch=${DRACUT_ARCH:-$(uname -m)}
    local _net_symbols='eth_type_trans|register_virtio_device|usbnet_open'
    local _unwanted_drivers='/(wireless|isdn|uwb|net/ethernet|net/phy|net/team)/'
    local _net_drivers

    if [[ $_arch == "s390" ]] || [[ $_arch == "s390x" ]]; then
        dracut_instmods -o -P ".*${_unwanted_drivers}.*" -s "$_net_symbols" "=drivers/s390/net"
    fi

    if [[ $hostonly_mode == 'strict' ]] && [[ -n ${hostonly_nics+x} ]]; then
        for _nic in $hostonly_nics; do
            mapfile -t _net_drivers < <(get_dev_module /sys/class/net/"$_nic")
            if ((${#_net_drivers[@]} == 0)); then
                derror "--hostonly-nics contains invalid NIC '$_nic'"
                continue
            fi
            hostonly="" instmods "${_net_drivers[@]}"
        done
        return 0
    fi

    dracut_instmods -o -P ".*${_unwanted_drivers}.*" -s "$_net_symbols" "=drivers/net"
    #instmods() will take care of hostonly
    instmods \
        '=drivers/net/mdio' \
        '=drivers/net/phy' \
        '=drivers/net/team' \
        '=drivers/net/ethernet' \
        ecb arc4 bridge stp llc ipv6 bonding 8021q ipvlan macvlan af_packet virtio_net xennet

    return 0

}

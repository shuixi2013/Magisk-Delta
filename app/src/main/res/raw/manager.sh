##################################
# Magisk app internal scripts
##################################

run_delay() {
  (sleep $1; $2)&
}

env_check() {
  for file in busybox magiskboot magiskinit util_functions.sh boot_patch.sh magisk.apk; do
    [ -f "$MAGISKBIN/$file" ] || return 1
  done
  if [ "$2" -ge 25000 ]; then
    [ -f "$MAGISKBIN/magiskpolicy" ] || return 1
  fi
  grep -xqF "MAGISK_VER='$1'" "$MAGISKBIN/util_functions.sh" || return 1
  grep -xqF "MAGISK_VER_CODE=$2" "$MAGISKBIN/util_functions.sh" || return 1
  return 0
}

cp_readlink() {
  if [ -z $2 ]; then
    cd $1
  else
    cp -af $1/. $2
    cd $2
  fi
  for file in *; do
    if [ -L $file ]; then
      local full=$(readlink -f $file)
      rm $file
      cp -af $full $file
    fi
  done
  chmod -R 755 .
  cd /
}

fix_env() {
  # Cleanup and make dirs
  rm -rf $MAGISKBIN/*
  if [ -d /data/unencrypted ]; then
      rm -rf $MAGISKBIN
      rm -rf /data/unencrypted/MAGISKBIN/*
      mkdir -p /data/unencrypted/MAGISKBIN
      ln -s ../unencrypted/MAGISKBIN $MAGISKBIN
  else
      mkdir -p $MAGISKBIN 2>/dev/null
  fi
  chmod 700 $NVBASE
  rm $1/stub.apk
  cp_readlink $1 $MAGISKBIN
  [ -z "$2" ] || cat "$2" >$MAGISKBIN/magisk.apk
  rm -rf $1
  chown -R 0:0 $MAGISKBIN
}

direct_install() {
  echo "- Flashing new boot image"
  flash_image $1/new-boot.img $2
  case $? in
    1)
      echo "! Insufficient partition size"
      return 1
      ;;
    2)
      echo "! $2 is read only"
      return 2
      ;;
  esac

  rm -f $1/new-boot.img
  fix_env "$1" "$3"
  install_addond "$3"
  run_migrations
  copy_sepolicy_rules

  return 0
}

run_uninstaller() {
  rm -rf /dev/tmp
  mkdir -p /dev/tmp/install
  unzip -o "$1" "assets/*" "lib/*" -d /dev/tmp/install
  INSTALLER=/dev/tmp/install sh /dev/tmp/install/assets/uninstaller.sh dummy 1 "$1"
}

restore_imgs() {
  [ -z $SHA1 ] && return 1
  local BACKUPDIR=/data/magisk_backup_$SHA1
  [ -d $BACKUPDIR ] || return 1

  get_flags
  find_boot_image

  for name in dtb dtbo; do
    [ -f $BACKUPDIR/${name}.img.gz ] || continue
    local IMAGE=$(find_block $name$SLOT)
    [ -z $IMAGE ] && continue
    flash_image $BACKUPDIR/${name}.img.gz $IMAGE
  done
  [ -f $BACKUPDIR/boot.img.gz ] || return 1
  flash_image $BACKUPDIR/boot.img.gz $BOOTIMAGE
}

post_ota() {
  cd $NVBASE
  cp -f $1 bootctl
  rm -f $1
  chmod 755 bootctl
  ./bootctl hal-info || return
  SLOT_NUM=0
  [ $(./bootctl get-current-slot) -eq 0 ] && SLOT_NUM=1
  ./bootctl set-active-boot-slot $SLOT_NUM
  cat << EOF > post-fs-data.d/post_ota.sh
/data/adb/bootctl mark-boot-successful
rm -f /data/adb/bootctl
rm -f /data/adb/post-fs-data.d/post_ota.sh
EOF
  chmod 755 post-fs-data.d/post_ota.sh
  cd /
}

add_hosts_module() {
  # Do not touch existing hosts module
  [ -d $MAGISKTMP/modules/hosts ] && return
  cd $MAGISKTMP/modules
  mkdir -p hosts/system/etc
  cat << EOF > hosts/module.prop
id=hosts
name=Systemless Hosts
version=1.0
versionCode=1
author=Magisk
description=Magisk app built-in systemless hosts module
EOF
  magisk --clone /system/etc/hosts hosts/system/etc/hosts
  touch hosts/update
  cd /
}

add_riru_core_module(){
    [ -d $MAGISKTMP/modules/riru-core ] && return
    mkdir -p $MAGISKTMP/modules/riru-core
    cat << EOF > $MAGISKTMP/modules/riru-core/module.prop
id=riru-core
name=Riru
version=N/A
versionCode=0
author=Rikka, yujincheng08
description=Riru module is not installed. Click update button to install the module.
updateJson=https://huskydg.github.io/external/riru-core/info.json
EOF
    cd /
}



adb_pm_install() {
  local tmp=/data/local/tmp/temp.apk
  cp -f "$1" $tmp
  chmod 644 $tmp
  su 2000 -c pm install -g $tmp || pm install -g $tmp || su 1000 -c pm install -g $tmp
  local res=$?
  rm -f $tmp
  if [ $res = 0 ]; then
    appops set "$2" REQUEST_INSTALL_PACKAGES allow 
    // Add magisk stub to sulist
    if magisk --hide sulist; then
      magisk --hide add "$2"
    fi
  fi
  return $res
}

check_boot_ramdisk() {
  # Create boolean ISAB
  ISAB=true
  [ -z $SLOT ] && ISAB=false

  # If we are A/B, then we must have ramdisk
  $ISAB && return 0

  # If we are using legacy SAR, but not A/B, assume we do not have ramdisk
  if grep ' / ' /proc/mounts | grep -q '^/dev/root'; then
    # Override recovery mode to true
    RECOVERYMODE=true
    return 1
  fi

  return 0
}

check_encryption() {
  if $ISENCRYPTED; then
    if [ $SDK_INT -lt 24 ]; then
      CRYPTOTYPE="block"
    else
      # First see what the system tells us
      CRYPTOTYPE=$(getprop ro.crypto.type)
      if [ -z $CRYPTOTYPE ]; then
        # If not mounting through device mapper, we are FBE
        if grep ' /data ' /proc/mounts | grep -qv 'dm-'; then
          CRYPTOTYPE="file"
        else
          # We are either FDE or metadata encryption (which is also FBE)
          CRYPTOTYPE="block"
          grep -q ' /metadata ' /proc/mounts && CRYPTOTYPE="file"
        fi
      fi
    fi
  else
    CRYPTOTYPE="N/A"
  fi
}

##########################
# Non-root util_functions
##########################

mount_partitions() {
  [ "$(getprop ro.build.ab_update)" = "true" ] && SLOT=$(getprop ro.boot.slot_suffix)
  # Check whether non rootfs root dir exists
  SYSTEM_ROOT=false
  ! is_rootfs && SYSTEM_ROOT=true
}

get_flags() {
  KEEPVERITY=$SYSTEM_ROOT
  ISENCRYPTED=false
  [ "$(getprop ro.crypto.state)" = "encrypted" ] && ISENCRYPTED=true
  KEEPFORCEENCRYPT=$ISENCRYPTED
  # Although this most certainly won't work without root, keep it just in case
  if [ -e /dev/block/by-name/vbmeta_a ] || [ -e /dev/block/by-name/vbmeta ]; then
    VBMETAEXIST=true
  else
    VBMETAEXIST=false
  fi
  # Preset PATCHVBMETAFLAG to false in the non-root case
  PATCHVBMETAFLAG=false
  # Make sure RECOVERYMODE has value
  [ -z $RECOVERYMODE ] && RECOVERYMODE=false
}

run_migrations() { return; }

grep_prop() { return; }

##############################
# Magisk Delta Custom script
##############################

is_delta(){
if magisk -v | grep -q "\-delta"; then
    return 0
fi
return 1
}

kill_magisk_shell() {
    pid_set=""
    for p in /proc/*/cmdline; do
        pid="${p%/*}"
        pid="${pid##*/}"
        if [ "$(cat /proc/$pid/attr/prev)" == "u:r:magisk:s0" ]; then
            pid_set="$pid $pid_set"
        fi
    done
    pid_set="$(echo "$pid_set" | sed "s/$$//g")"
    kill -SIGKILL $pid_set
}

unload_magisk(){
    kill_magisk_shell; magisk --stop && { setprop ctl.restart zygote; }
}

coreonly(){
    local i presistdir="/data/adb /data/unencrypted /persist /mnt/vendor/persist /cache /metadata"
    if [ "$1" == "enable" ] || [ "$1" == "disable" ]; then
        for i in $presistdir; do
            rm -rf "$i/.disable_magisk"
            [ "$1" == "disable" ] || touch "$i/.disable_magisk"
        done
        return 0
    else
        for i in $presistdir; do
            [ -e "$i/.disable_magisk" ] && return 0
        done
        return 1
    fi
}

use_full_magisk(){
    [ "$(magisk --path)" == "/system/xbin" ] && return 1
    return 0
}

install_addond(){
    local installDir="$MAGISKBIN"
    local AppApkPath="$1"
    local SYSTEM_INSTALL="$2"
    [ -z "$SYSTEM_INSTALL" ] && SYSTEM_INSTALL=false
    addond=/system/addon.d
    test ! -d $addond && return
    ui_print "- Adding addon.d survival script"
    BLOCKNAME="/dev/block/system_block.$(random_str 5 20)"
    rm -rf "$BLOCKNAME"
    if is_rootfs; then
        mkblknode "$BLOCKNAME" /system
    else
        mkblknode "$BLOCKNAME"  /
    fi
    blockdev --setrw "$BLOCKNAME"
    rm -rf "$BLOCKNAME"
    mount -o rw,remount /
    mount -o rw,remount /system
    rm -rf $addond/99-magisk.sh 2>/dev/null
    rm -rf $addond/magisk 2>/dev/null
    if [ "$SYSTEM_INSTALL" == "true" ]; then
        cp -prLf "$installDir"/. /system/etc/init/magisk || { ui_print "! Failed to install addon.d"; return; }
        mv "$installDir/addon.d.sh" $addond/99-magisk.sh
        cp "$AppApkPath" /system/etc/init/magisk/magisk.apk
        chmod 755 /system/etc/init/magisk/*
        sed -i "s/^SYSTEMINSTALL=.*/SYSTEMINSTALL=true/g" $addond/99-magisk.sh
    else
        mkdir -p $addond/magisk
        cp -prLf "$installDir"/. $addond/magisk || { ui_print "! Failed to install addon.d"; return; }
        mv $addond/magisk/boot_patch.sh $addond/magisk/boot_patch.sh.in
        mv $addond/magisk/addon.d.sh $addond/99-magisk.sh
        cp "$AppApkPath" $addond/magisk/magisk.apk
    fi
    mount -o ro,remount /
    mount -o ro,remount /system
}
    
check_system_magisk(){
    ALLOWSYSTEMINSTALL=true
    local SHA1 SYSTEMMODE=false
    if command -v magisk &>/dev/null; then
       local MAGISKTMP="$(magisk --path)/.magisk" || return
       getvar SHA1
       getvar SYSTEMMODE
    fi
    # do not allow installing magisk as system mode if Magisk is in boot image
    [ -z "$SHA1" ] || ALLOWSYSTEMINSTALL=false
    # allow if SYSTEMMODE=true
    [ "$SYSTEMMODE" == "true" ] && ALLOWSYSTEMINSTALL=true
}

clean_hidelist(){
    local tab=hidelist
    if [ "$SULISTMODE" == "true" ]; then
        tab=sulist
    fi
    local PACKAGE_NAME="$(magisk --sqlite "SELECT package_name FROM $tab WHERE package_name NOT IN ('isolated')")"
    local PACKAGE_LIST=""
    # isolation service
    local PACKAGE_ISOLIST="$(magisk --sqlite "SELECT process FROM $tab WHERE package_name IN ('isolated')")"
    local s t exist
    for s in $PACKAGE_NAME; do
        if [ "${s: 13}" == "isolated" ]; then
            continue
        fi
        exist=false
        for t in $PACKAGE_LIST; do
            if [ "$t" == "${s: 13}" ]; then
                exist=true
                break;
            fi
        done
        if ! $exist; then
            PACKAGE_LIST="$PACKAGE_LIST ${s: 13}"
        fi
    done
    for s in $PACKAGE_LIST; do
        if [ ! -d "/data/data/$s" ]; then
            magisk --hide rm "$s"
            for t in $(echo "$PACKAGE_ISOLIST" | grep "$s"); do
                t="${t: 8}"
                magisk --hide rm isolated "$t"
            done
        fi
    done
}

get_sulist_status(){
    SULISTMODE=false
    if magisk --hide sulist; then
        SULISTMODE=true
    fi
}

##############################
# Magisk Delta Custom install script
##############################

# define
MAGISKSYSTEMDIR="/system/etc/init/magisk"

random_str(){
local FROM
local TO
FROM="$1"; TO="$2"
tr -dc A-Za-z0-9 </dev/urandom | head -c $(($FROM+$(($RANDOM%$(($TO-$FROM+1))))))
}

magiskrc(){
local MAGISKTMP="/sbin"

# use "magisk --auto-selinux" to automatically switching selinux state

cat <<EOF

on post-fs-data
    start logd
    exec u:r:su:s0 root root -- $MAGISKSYSTEMDIR/magiskpolicy --live --magisk
    exec u:r:magisk:s0 root root -- $MAGISKSYSTEMDIR/magiskpolicy --live --magisk
    exec u:r:update_engine:s0 root root -- $MAGISKSYSTEMDIR/magiskpolicy --live --magisk
    exec u:r:su:s0 root root -- $MAGISKSYSTEMDIR/$magisk_name --auto-selinux --setup-sbin $MAGISKSYSTEMDIR
    mkdir $MAGISKTMP/.magisk 700
    mkdir $MAGISKTMP/.magisk/mirror 700
    mkdir $MAGISKTMP/.magisk/block 700
    copy $MAGISKSYSTEMDIR/config $MAGISKTMP/.magisk/config
    rm /dev/.magisk_unblock
    exec u:r:su:s0 root root -- $MAGISKTMP/magisk --auto-selinux --post-fs-data
    wait /dev/.magisk_unblock 40
    rm /dev/.magisk_unblock

on nonencrypted
    exec u:r:su:s0 root root -- $MAGISKTMP/magisk --auto-selinux --service

on property:sys.boot_completed=1
    mkdir /data/adb/magisk 755
    exec u:r:su:s0 root root -- $MAGISKTMP/magisk --auto-selinux --boot-complete
   
on property:init.svc.zygote=restarting
    exec u:r:su:s0 root root -- $MAGISKTMP/magisk --auto-selinux --zygote-restart
   
on property:init.svc.zygote=stopped
    exec u:r:su:s0 root root -- $MAGISKTMP/magisk --auto-selinux --zygote-restart


EOF
}

remount_check(){
    local mode="$1"
    local part="$(realpath "$2")"
    local ignore_not_exist="$3"
    local i
    if ! grep -q " $part " /proc/mounts && [ ! -z "$ignore_not_exist" ]; then
        return "$ignore_not_exist"
    fi
    mount -o "$mode,remount" "$part"
    local IFS=$'\t\n ,'
    for i in $(cat /proc/mounts | grep " $part " | awk '{ print $4 }'); do
        test "$i" == "$mode" && return 0
    done
    return 1
}

backup_restore(){
    # if gz is not found and orig file is found, backup to gz
    if [ ! -f "${1}.gz" ] && [ -f "$1" ]; then
        gzip -k "$1" && return 0
    elif [ -f "${1}.gz" ]; then
    # if gz found, restore from gz
        rm -rf "$1" && gzip -kdf "${1}.gz" && return 0
    fi
    return 1
}

restore_from_bak(){
    backup_restore "$1" && rm -rf "${1}.gz"
}

cleanup_system_installation(){
    rm -rf "$MIRRORDIR${MAGISKSYSTEMDIR}"
    rm -rf "$MIRRORDIR${MAGISKSYSTEMDIR}.rc"
    backup_restore "$MIRRORDIR/system/etc/init/bootanim.rc" \
    && rm -rf "$MIRRORDIR/system/etc/init/bootanim.rc.gz"
    if [ -e "$MIRRORDIR${MAGISKSYSTEMDIR}" ] || [ -e "$MIRRORDIR${MAGISKSYSTEMDIR}.rc" ]; then
        return 1
    fi
}

unmount_system_mirrors(){
    if $BOOTMODE; then
        umount -l "/dev/sysmount_mirror"
        rm -rf "/dev/sysmount_mirror"
    else
        recovery_cleanup
    fi
}

print_title_delta(){
    print_title "Magisk Delta (Systemless Mode)" "by HuskyDG"
    print_title "Powered by Magisk"
    return 0
}

direct_install_system(){
    print_title "Magisk Delta (System Mode)" "by HuskyDG"
    print_title "Powered by Magisk"
    api_level_arch_detect
    local INSTALLDIR="$1"
        
    ui_print "- Remount system partition as read-write"
    local MIRRORDIR="/dev/sysmount_mirror" ROOTDIR SYSTEMDIR VENDORDIR

    ROOTDIR="$MIRRORDIR/system_root"
    SYSTEMDIR="$MIRRORDIR/system"
    VENDORDIR="$MIRRORDIR/vendor"
    
    if $BOOTMODE; then
        # setup mirrors to get the original content
        umount -l "$MIRRORDIR" 2>/dev/null
        rm -rf "$MIRRORDIR"
        mkdir -p "$MIRRORDIR" || return 1
        mount -t tmpfs -o 'mode=0755' tmpfs "$MIRRORDIR" || return 1
        if is_rootfs; then
            ROOTDIR=/
            mkdir "$SYSTEMDIR"
            force_bind_mount "/system" "$SYSTEMDIR" || return 1
        else
            mkdir "$ROOTDIR"
            force_bind_mount "/" "$ROOTDIR" || return 1
            if mountpoint -q /system; then
                mkdir "$SYSTEMDIR"
                force_bind_mount "/system" "$SYSTEMDIR" || return 1
            else
                ln -fs ./system_root/system "$SYSTEMDIR"
            fi
            if [ ! -d "$ROOTDIR/sbin" ]; then
                # create dummy sbin for Android 11+
                rm -rf "$ROOTDIR/sbin"
                mkdir -p "$ROOTDIR/sbin"
                chcon u:object_r:rootfs:s0 "$ROOTDIR/sbin"
                chmod 700 "$ROOTDIR/sbin"
            fi
        fi

        # check if /vendor is seperated fs
        if mountpoint -q /vendor; then
            mkdir "$VENDORDIR"
            force_bind_mount "/vendor" "$VENDORDIR" || return 1
         else
            ln -fs ./system/vendor "$VENDORDIR"
        fi
    else
        local MIRRORDIR="/" ROOTDIR SYSTEMDIR VENDORDIR
        ROOTDIR="$MIRRORDIR/system_root"
        SYSTEMDIR="$MIRRORDIR/system"
        VENDORDIR="$MIRRORDIR/vendor"
        ui_print "- Mount system partitions as read-write..."
        remount_check rw "$ROOTDIR" 0 || { warn_system_ro; return 1; }
        remount_check rw "$SYSTEMDIR" 0 || { warn_system_ro; return 1; }
        remount_check rw "$VENDORDIR" 0 || { warn_system_ro; return 1; }
    fi
        

    ui_print "- Cleaning up enviroment..."
    local checkfile="$MIRRORDIR/system/.check_$(random_str 10 20)"
    # test write, need atleast 30mb
    dd if=/dev/zero of="$checkfile" bs=1024 count=30000 || { rm -rf "$checkfile"; ui_print "! Insufficient free space or system write protection"; return 1; }
    rm -rf "$checkfile"
    cleanup_system_installation || return 1

    local magisk_applet=magisk32 magisk_name=magisk32
    if [ "$IS64BIT" == true ]; then
        magisk_name=magisk64
        magisk_applet="magisk32 magisk64"
    fi

    ui_print "- Copy files to system partition"
    mkdir -p "$MIRRORDIR$MAGISKSYSTEMDIR" || return 1
    for magisk in $magisk_applet magiskpolicy magiskinit stub.apk; do
        cat "$INSTALLDIR/$magisk" >"$MIRRORDIR$MAGISKSYSTEMDIR/$magisk" || { ui_print "! Unable to write Magisk binaries to system"; return 1; }
    done
    echo -e "SYSTEMMODE=true\nRECOVERYMODE=false" >"$MIRRORDIR$MAGISKSYSTEMDIR/config"
    chcon -R u:object_r:system_file:s0 "$MIRRORDIR$MAGISKSYSTEMDIR"
    chmod -R 700 "$MIRRORDIR$MAGISKSYSTEMDIR"

    if [ "$API" -gt 24 ]; then

        # test live patch
        {
            if $BOOTMODE; then
                ui_print "- Check if kernel supports dynamic SELinux Policy patch"
                if [ -d /sys/fs/selinux ] && ! "$INSTALLDIR/magiskpolicy" --live "permissive su" &>/dev/null; then
                    ui_print "! Kernel does not support dynamic SELinux Policy patch"
                    return 1
                fi
            else
                ui_print "W: It's impossible to check kernel compatible in recovery mode"
                ui_print "W: Please make sure your kernel can dynamic patch SELinux Policy"
            fi
            if ! is_rootfs; then
              {
                ui_print "- Patch sepolicy file"
                local sepol file
                for file in /vendor/etc/selinux/precompiled_sepolicy /system_root/odm/etc/selinux/precompiled_sepolicy /system/etc/selinux/precompiled_sepolicy /system_root/sepolicy /system_root/sepolicy_debug /system_root/sepolicy.unlocked; do
                    if [ -f "$MIRRORDIR$file" ]; then
                        sepol="$file"
                        break
                    fi
                done
                if [ -z "$sepol" ]; then
                    ui_print "! Cannot find sepolicy file"
                    return 1
                else
                    ui_print "- Target sepolicy is $sepol"
                    backup_restore "$MIRRORDIR$sepol" || { ui_print "! Backup failed"; return 1; }
                    # copy file to cache
                    cp -af "$MIRRORDIR$sepol" "$INSTALLDIR/sepol.in"
                    if ! "$INSTALLDIR/magiskinit" --patch-sepol "$INSTALLDIR/sepol.in" "$INSTALLDIR/sepol.out" || ! cp -af "$INSTALLDIR/sepol.out" "$MIRRORDIR$sepol"; then
                        ui_print "! Unable to patch sepolicy file"
                        restore_from_bak "$MIRRORDIR$sepol"
                        return 1
                    fi
                    ui_print "- Patching sepolicy file success!"
                fi
              }
            fi
        }
        ui_print "- Add init boot script"
        {
            hijackrc="$MIRRORDIR/system/etc/init/magisk.rc"
            if [ -f "$MIRRORDIR/system/etc/init/bootanim.rc" ]; then
                backup_restore "$MIRRORDIR/system/etc/init/bootanim.rc" && hijackrc="$MIRRORDIR/system/etc/init/bootanim.rc"
            fi
        }
        echo "$(magiskrc)" >>"$hijackrc" || return 1
    elif [ "$API" -gt 19 ]; then
        cat "$INSTALLDIR/busybox" >"$MIRRORDIR$MAGISKSYSTEMDIR/busybox" || { ui_print "! Unable to write Magisk binaries to system"; return 1; }
        chmod 755 "$MIRRORDIR$MAGISKSYSTEMDIR/busybox"
        if [ ! -f "$MIRRORDIR/system/bin/app_process.orig" ]; then
            rm -rf "$MIRRORDIR/system/bin/app_process.orig"
            mv -f "$MIRRORDIR/system/bin/app_process" "$MIRRORDIR/system/bin/app_process.orig"
        fi
        rm -rf "$MIRRORDIR/system/bin/app_process"
        # hijack app_process to launch magisk su
        cat <<EOF >"$MIRRORDIR/system/bin/app_process"
#!/system/etc/init/magisk/busybox sh
set -o standalone
setenforce 0
setup_magisk(){
    mount --bind /system/bin/app_process.orig "\$(realpath "\$0")"
    "$MAGISKSYSTEMDIR/$magisk_name" --setup-sbin "$MAGISKSYSTEMDIR"
    mkdir -p /sbin/.magisk/mirror
    mkdir -p /sbin/.magisk/block
    echo -e "SYSTEMMODE=true\nRECOVERYMODE=false" >/sbin/.magisk/config
    # run magisk daemon
    /sbin/magisk --post-fs-data
    i=0
    while [ ! -f /dev/.magisk_unblock ]; do
        i=\$((\$i+1))
        if [ "\$i" -gt 40 ]; then
            break
        fi
        sleep 1;
    done
    rm -rf /dev/.magisk_unblock
    /sbin/magisk --service
    (
      while [ "$(getprop sys.boot_completed)" != 1 ]; do sleep 1; done
      /sbin/magisk --boot-complete
    ) &
} 

setup_magisk; exec /system/bin/app_process.orig "\$@"
EOF
        chmod 755 "$MIRRORDIR/system/bin/app_process"
    fi

    $BOOTMODE && unmount_system_mirrors
    ui_print "[*] Reflash your ROM if your ROM is unable to start"
    ui_print "    and do not use this method to install Magisk" 
    true
    return 0
}


xdirect_install_system() {
  direct_install_system "$@" || { cleanup_system_installation; unmount_system_mirrors; return 1; }
  fix_env "$1" "$3"
  install_addond "$3" "true"
  run_migrations
  copy_sepolicy_rules
  return 0
}
  


#############
# Initialize
#############

app_init() {
  mount_partitions
  RAMDISKEXIST=false
  check_boot_ramdisk && RAMDISKEXIST=true
  get_flags
  run_migrations
  SHA1=$(grep_prop SHA1 $MAGISKTMP/config)
  check_encryption
  check_system_magisk
  get_sulist_status
}

export BOOTMODE=true

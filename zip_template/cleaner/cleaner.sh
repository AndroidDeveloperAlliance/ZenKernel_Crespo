#!/sbin/sh
# mount /system and /data partitions
mount -o rw /dev/block/platform/s3c-sdhci.0/by-name/system /system
mount -o rw /dev/block/platform/s3c-sdhci.0/by-name/userdata /data

# clean modules
rm -f /system/modules/*
rm -f /system/lib/modules/*

# clean boot sound
rm -f /system/media/audio/poweron/PowerOn.*
rm -f /system/media/audio/poweron/poweron.*

# clean init.d scripts
INITD_DIR=/system/etc/init.d
# GLaDOS
rm -f $INITD_DIR/90logger
rm -f $INITD_DIR/99nexusinit
rm -f $INITD_DIR/placeholder
# Trinity
rm -f $INITD_DIR/95dimmers
rm -f $INITD_DIR/98tweak
rm -f $INITD_DIR/99complete
# SG
rm -f $INITD_DIR/98_startup_script
rm -f $INITD_DIR/99_startup_complete
# Air
rm -f $INITD_DIR/35airtweaks
# miscellany
rm -f $INITD_DIR/99nstools
# JellyBelly (embarrassed...)
rm -f $INITD_DIR/00kernel
# Zen
rm -f $INITD_DIR/99ZenKernel

# clean kernel setting app shared_prefs
rm -rf /data/data/mobi.cyann.nstools/shared_prefs
rm -rf /data/data/aperture.ezekeel.gladoscontrol/shared_prefs
rm -rf /data/data/com.derkernel.tkt/shared_prefs
rm -rf /data/data/com.franco.kernel/shared_prefs
rm -rf /data/data/com.liquid.control/shared_prefs
rm -rf /data/data/org.projectvoodoo.controlapp/shared_prefs/color_settings.xml

# unmount /system and /data partitions
umount /system
umount /data

pic=`date +%s`.png
adb shell screencap -p /sdcard/$pic
adb pull /sdcard/$pic ./screen/$pic
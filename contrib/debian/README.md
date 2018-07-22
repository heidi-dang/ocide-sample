
Debian
====================
This directory contains files used to package ocided/ocide-qt
for Debian-based Linux systems. If you compile ocided/ocide-qt yourself, there are some useful files here.

## ocide: URI support ##


ocide-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install ocide-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your ocide-qt binary to `/usr/bin`
and the `../../share/pixmaps/ocide128.png` to `/usr/share/pixmaps`

ocide-qt.protocol (KDE)



Debian
====================
This directory contains files used to package tourd/tour-qt
for Debian-based Linux systems. If you compile tourd/tour-qt yourself, there are some useful files here.

## tour: URI support ##


tour-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install tour-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your tour-qt binary to `/usr/bin`
and the `../../share/pixmaps/tour128.png` to `/usr/share/pixmaps`

tour-qt.protocol (KDE)


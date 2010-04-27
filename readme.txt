zynamics Objective-C helper script


Description
-----------

This is an idapython script that analyzes ARM/Objective-C files in
order to patch calls made to msgSend(), in order to have a better
callgraph and more useful cross references. A bit of extra information
can be found on:

http://blog.zynamics.com/2010/04/27/objective-c-reversing-i/


Prerequisites
----------

The script has been developed and tested using IDA 5.6 and idapython
1.3.0 but it should work with older versions.


License
-------

The Objective-C helper script is GPLv2-licensed. If you prefer to distribute
code from the script under another license please contact us to learn about
re-licensing options.

Objective-C helper script
Copyright (C) 2010 zynamics GmbH

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program;
if not, write to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA



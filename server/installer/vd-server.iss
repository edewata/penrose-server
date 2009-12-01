; Copyright 2009 Red Hat, Inc.
;
; This program is free software; you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation; either version 2 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program; if not, write to the Free Software
; Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

[Setup]

AppName=${product.title}
AppVerName=${product.title} ${product.version}
DefaultDirName={pf}\${product.group}\${product.title} ${product.version}
DefaultGroupName=${product.group}\${product.title} ${product.version}
UninstallDisplayName=${product.title} ${product.version}
UninstallDisplayIcon={app}\${images.icon}
Compression=zip
SolidCompression=yes
OutputBaseFilename=${product.name}-${product.version}
OutputDir=..\..\dist
LicenseFile=dist\LICENSE.txt

[Files]

Source: "dist\*"; DestDir: "{app}"; Components: main
Source: "dist\bin\*"; DestDir: "{app}\bin"; Components: main
Source: "dist\conf\*"; DestDir: "{app}\conf"; Flags: onlyifdoesntexist uninsneveruninstall; Components: main
Source: "dist\docs\*"; DestDir: "{app}\docs"; Flags: recursesubdirs; Components: docs
Source: "dist\lib\*"; DestDir: "{app}\lib"; Flags: recursesubdirs; Components: main
Source: "dist\server\lib\*"; DestDir: "{app}\server\lib"; Flags: recursesubdirs; Components: main
Source: "dist\schema\*"; DestDir: "{app}\schema"; Flags: recursesubdirs; Components: main
Source: "dist\services\*"; DestDir: "{app}\services"; Flags: recursesubdirs; Components: main
Source: "dist\samples\*"; DestDir: "{app}\samples"; Flags: recursesubdirs; Components: sample

[Dirs]

Name: "{app}\docs"
Name: "{app}\lib\ext"
Name: "{app}\partitions"
Name: "{app}\samples"
Name: "{app}\server\lib\ext"
Name: "{app}\services\OpenDS\db"
Name: "{app}\services\OpenDS\locks"
Name: "{app}\services\OpenDS\logs"
Name: "{app}\schema\ext"
Name: "{app}\var"

[Components]

Name: "main"; Description: "Main Files"; Types: full compact custom; Flags: fixed
Name: "docs"; Description: "Documentations"; Types: full
Name: "sample"; Description: "Sample Files"; Types: full

[Icons]

Name: "{group}\Documentation\README.txt"; Filename: "{app}\README.txt"
Name: "{group}\Documentation\LICENSE.txt"; Filename: "{app}\LICENSE.txt"
Name: "{group}\Documentation\COPYING.txt"; Filename: "{app}\COPYING.txt"
Name: "{group}\Documentation\INSTALL-BINARY.txt"; Filename: "{app}\INSTALL-BINARY.txt"
Name: "{group}\Documentation\Penrose API"; Filename: "{app}\docs\javadoc\index.html"; Flags: createonlyiffileexists;
Name: "{group}\Documentation\Online Documentation"; Filename: "{app}\docs\Online Documentation.url";
Name: "{group}\Documentation\Penrose Website"; Filename: "{app}\docs\Penrose Website.url";
Name: "{group}\Documentation\Safehaus Website"; Filename: "{app}\docs\Safehaus Website.url";
Name: "{group}\${product.title}"; Filename: "{app}\bin\vd-server.bat"; IconFilename: "{app}\${images.icon}"; WorkingDir: "{app}"
Name: "{group}\Configuration Files"; Filename: "{app}\conf";
Name: "{group}\Sample Files"; Filename: "{app}\samples";
Name: "{group}\Schema Files"; Filename: "{app}\schema";
Name: "{group}\Windows Service\Start Service"; Filename: "{sys}\net.exe"; Parameters: "start ""${product.title} ${product.version}"""; IconFilename: "{app}\${images.icon}"; WorkingDir: "{app}"
Name: "{group}\Windows Service\Stop Service"; Filename: "{sys}\net.exe"; Parameters: "stop ""${product.title} ${product.version}"""; IconFilename: "{app}\${images.icon}"; WorkingDir: "{app}"
Name: "{group}\Windows Service\Register Service"; Filename: "{app}\bin\vd-service.bat"; Parameters: "install"; IconFilename: "{app}\${images.icon}"; WorkingDir: "{app}"
Name: "{group}\Windows Service\Unregister Service"; Filename: "{app}\bin\vd-service.bat"; Parameters: "uninstall"; IconFilename: "{app}\${images.icon}"; WorkingDir: "{app}"
Name: "{group}\Uninstall ${product.title}"; Filename: "{uninstallexe}"

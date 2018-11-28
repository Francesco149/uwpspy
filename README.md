dll that hooks various uwp interfaces for debugging and reverse engineering

# compiling
install visual c++ build tools 2017 and the windows 10 sdk

open powershell and navigate to uwpspy

```ps1
.\vcvarsall17.ps1
.\build.ps1
```

# usage
use an injector that can fix permissions for uwp apps like
https://github.com/Francesco149/uwpinject

a console should pop up and start logging on injection

# PGHooker
 
## Function hooking example

```cpp
#include <iostream>

#include "PGHooker.hpp"

int WINAPI hkMessageBoxA( HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType )
{
    printf( "MessageBoxA hook called !!! \n" );

    PGHooker::DisableHookForOnce( MessageBoxA );
    return MessageBoxA( hWnd, lpText, lpCaption, uType );
}

int main( )
{
    PGHooker::Initialize( );
    PGHooker::CreateHook( MessageBoxA, hkMessageBoxA );

    printf( "Calling MessageBoxA \n" );

    MessageBoxA( NULL, "Text", "Caption", MB_ICONINFORMATION );
    
    printf( "End! \n" );

    return 0;
}
```
## Console output
```
Calling MessageBoxA
MessageBoxA hook called !!!
End!
```

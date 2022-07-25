#include <iostream>

#include "PGHooker.hpp"

void PGHAPI CallbackRead0( PCONTEXT pCtx, E_CallbackFlags eType )
{
    printf( "-- CallbackRead0 \n" );
}

void PGHAPI CallbackWrite1( PCONTEXT pCtx, E_CallbackFlags eType )
{
    printf( "-- CallbackWrite1 \n" );
}

void PGHAPI CallbackReadWrite2( PCONTEXT pCtx, E_CallbackFlags eType )
{
    printf( "-- CallbackReadWrite2: %d \n", eType );
}

int WINAPI hkMessageBoxA( HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType )
{
    printf( "MessageBoxA hook called !!! \n" );

    PGHooker::DisableHookForOnce( MessageBoxA );
    return MessageBoxA( hWnd, lpText, lpCaption, uType );
}

int main()
{
    PGHooker::Initialize( );

    printf( "RW hooking test \n--- \n" );
    { 
        volatile int temp {};
        volatile int* pMas = ( int* ) VirtualAlloc( NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

        PGHooker::CreateCallback( ( int* ) pMas, CF_READ, CallbackRead0 );
        PGHooker::CreateCallback( ( int* ) pMas + 1, CF_WRITE, CallbackWrite1 );
        PGHooker::CreateCallback( ( int* ) pMas + 2, CF_READ | CF_WRITE, CallbackReadWrite2 );

        printf( "reading pMas[0] \n" );
        temp = pMas[ 0 ];

        printf( "writing pMas[1] \n" );
        pMas[ 1 ] = 1;

        printf( "writing & reading pMas[2] \n" );
        pMas[ 2 ] = temp;
        temp = pMas[ 2 ];

        PGHooker::RemoveCallback( ( int* ) pMas );
        PGHooker::RemoveCallback( ( int* ) pMas + 1 );
    }

    printf( "\nFunction hooking test \n--- \n" );
    {
        PGHooker::CreateHook( MessageBoxA, hkMessageBoxA );

        printf( "Calling MessageBoxA \n" );

        MessageBoxA( NULL, "Text", "Caption", MB_ICONINFORMATION );

        PGHooker::RemoveHook( MessageBoxA );
    }

    PGHooker::Uninitilize( ); // also this function removes PAGE_GUARD from all used pages 

    printf( "End! \n" );

    return 0;
}

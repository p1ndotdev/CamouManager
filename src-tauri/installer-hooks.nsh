!macro NSIS_HOOK_PREINSTALL
  ; Legacy profile data lives here: never install binaries into the data directory.
  ${If} $INSTDIR == "$LOCALAPPDATA\CamouManager"
    StrCpy $INSTDIR "$LOCALAPPDATA\Programs\CamouManager"
    ; Tauri sets $OUTDIR before this hook; keep relative resource extraction in sync.
    SetOutPath $INSTDIR
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    SetShellVarContext current
    RMDir /r "$LOCALAPPDATA\CamouManagerRust"
  ${EndIf}
!macroend

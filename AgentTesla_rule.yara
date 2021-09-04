rule Agent_Tesla
{
    meta:
        description = "agent-tesla"
        maltype = "trojan"
	date = "8/27/2021"

    strings:
        $var1 = "46599D29C9831138B75ED7B25049144259139724"
	$var2 = "ArVX"
	$var3 = "AzM"
	$var4 = "a4attempt4.exe"
    
    condition:
        $var1 and $var2 and $var3 and $var4
}

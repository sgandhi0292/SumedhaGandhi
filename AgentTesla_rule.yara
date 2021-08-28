rule Agent_Tesla
{
    meta:
        description = "agent-tesla"
        maltype = "trojan"
	date = "8/27/2021"

    strings:
        $var1 = "This program cannot be run in DOS mode"
	$var2 = "ArVX"
	$var3 = "AzM"
	$var4 = "a4attempt4"
    
    condition:
        $var1 and $var2 and $var3 and $var4
}

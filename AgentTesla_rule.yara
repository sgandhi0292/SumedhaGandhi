rule Agent_Tesla
{
    meta:
        description = "agent-tesla"
		File 1 = "0abb52b3e0c08d5e3713747746b019692a05c5ab8783fd99b1300f11ea59b1c9"
        maltype = "trojan"

    strings:
        $var1 = "This program cannot be run in DOS mode"
		$var2 = "ArVX"
		$var3 = "AzM"
		$var4 = "a4attempt4"
    
    condition:
        $var1 and $var2 and $var3 and $var4
}
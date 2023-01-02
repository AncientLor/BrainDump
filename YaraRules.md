# YARA - Yet Another Ridiculous Acronym

_"The pattern matching swiss knife for malware researchers (and everyone else)" -Virustotal_

- Uses rules to detect patterns/signatures (strings) within files on your operating system.

#### Example:

```
print("Hello World")
```

We could use a Yara rule to search for "hello world" in every program on our system. We could also search for other strings such as the ones listed below:

**Ransomware**

12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw (Bitcoin Wallet)

**Botnet**

12.34.56.7 (C2 IP)				

## Yara Rules

#### **_Anatomy of a Yara Rule:_** https://miro.medium.com/max/1400/1*gThGNPenpT-AS-gjr8JCtA.webp

Every yara command requires two arguments to be valid, these are:

1) The rule file we create
2) Name of file, directory, or process ID to use the rule for.

Every rule must have a name and a condition.

*Example:*

```
yara rule.yar directory
```

*Example Rule:*

```
rule examplerule {          // name
        condition: true     // condition
}
```
- Checks to see if the file/directory/PID that we specify exists via condition: true

- Will return name of rule if conditions are met and error if not.

*Other Conditions:*

```
Desc            // summary of what rule checks for
Meta            // descriptive information from author
Strings         // search for specific text or hexadecimal strings
Conditions      // 
Weight          //
```

*Example:*

```
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!"
    
    condition:
		$hello_world
}
```
This rule will search for the literal string "Hello World!" and will not detect strings using different capitalization. To account for this, we can use the modified code below to search for more that one string entry at a time.

```
rule helloworld_checker{
	strings:
		$hello_world = "Hello World!"
		$hello_world_lowercase = "hello world"
		$hello_world_uppercase = "HELLO WORLD"

	condition:
		any of them
}
```
----------------

### Conditions:

```
true
false
any of them
```

### Operators:

```
<=          // less than or equal to
>=          // more than or equal to
!=          // not equal to
and
not
or
```

### More Keywords:

```
filesize



```




## Other Resources

```
Cuckoo
Cuckoo Sandbox is an automated malware analysis environment. This module allows you to generate Yara rules based upon the behaviours discovered from Cuckoo Sandbox. As this environment executes malware, you can create rules on specific behaviours such as runtime strings and the like.
```
```
Python PE
Python's PE module allows you to create Yara rules from the various sections and elements of the Windows Portable Executable (PE) structure.
```

- https://cuckoosandbox.org/
- https://pypi.org/project/pefile/
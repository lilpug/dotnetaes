## DotNetAES

DotNetAES is an AES CBC .NET wrapper which makes it easy to encrypt data, objects and files, it also utilises GZIP internally to help keep the encrypted data size as small as it can be.

[![NuGet](https://img.shields.io/nuget/v/DotNetAES.svg?maxAge=3600)](https://www.nuget.org/packages/DotNetAES/)

## Security Information

It is highly recommended that you keep your encryption key and IV's seperate. 

Its also recommended that you regenerate your IVs for every call of the encryption functions.


## Getting Started
Download and reference the release DLL file in your project.

Add the following namespace and then your ready to use the functionality in the library.
```C#
using DotNetAES;
```




## Encryption Functions

**NOTE: All encryption functions will accept the key and IV in either base64 string or byte array formats.**


### EncryptToString
This function encrypts a specified object into a base64 encrypted string.

Syntax
```C#
string EncryptToString(object data, object key, object IV)
```

Example Usage
```C#
string exampleString = "this is a test string.";

//Generates a key and IV for the example
string key = AES.CreateStringKey();
string IV = AES.CreateStringIV();

//Encrypts the string
string encryptedString = AES.EncryptToString(exampleString, key, IV);
```


### EncryptToBytes
This function encrypts a specified object into a byte array.

Syntax
```C#
byte[] EncryptToBytes(object data, object key, object IV)
```

Example Usage
```C#
string exampleString = "this is a test string.";

//Generates a key and IV for the example
string key = AES.CreateStringKey();
string IV = AES.CreateStringIV();

//Encrypts the string into bytes
byte[] encryptedBytes = AES.EncryptToBytes(exampleString, key, IV);
```


### SaveEncryptedFile
This function encrypts some supplied data and then saves it at the specified location.

Syntax
```C#
bool SaveEncryptedFile(string path, byte[] fileData, object key, object IV)
```

Example Usage
```C#
//Generates a key and IV for the example
string key = AES.CreateStringKey();
string IV = AES.CreateStringIV();

//Reads the file data like normal
byte[] file = File.ReadAllBytes("C:\1.jpg");

//Saves the loaded file data as an encrypted file
bool encryptedCheck = AES.SaveEncryptedFile($@"C:\1_encrypted.jpg", file, key, IV);
```


### LoadEncryptedFile
This function loads a file from the path specified and returns the encrypts version of it.

Syntax
```C#
byte[] LoadEncryptedFile(string path, object key, object IV)
```

Example Usage
```C#
//Generates a key and IV for the example
string key = AES.CreateStringKey();
string IV = AES.CreateStringIV();

//Loads the file data and gets the encrypted version of it
byte[] encryptedCheck = AES.LoadEncryptedFile($@"C:\1.jpg", key, IV);
```




## Decryption Functions

**NOTE: All decryption functions will accept the key, IV and encrypted data in either base64 string or byte array formats.**


### DecryptToType
This function decrypts the supplied encryption string or byte array into a specified object type.

**Note: The type for the decryption MUST be the original type the data was before it was encrypted.**

Syntax
```C#
T DecryptToType<T>(object data, object key, object IV)
```

Example Usage
```C#
string exampleString = "this is a test string.";

//Generates a key and IV for the example
string key = AES.CreateStringKey();
string IV = AES.CreateStringIV();

//Encrypts the string
string encryptedString = AES.EncryptToString(exampleString, key, IV);

//Decrypts the string base64 encrypted string back into a string format
string decryptedString = AES.DecryptToType<string>(encryptedString, key, IV);
```

Object Example
```C#
//NOTE: for a class object to be encrypted it has to have the Serializable flag on it as thats how we process the data before encryption
[Serializable]
public class TestUser
{
	public string Name { get; set; }
	public int Age { get; set; }
}

private static bool ObjectEncryption()
{
	//Generates a key and IV for the example
	string key = AES.CreateStringKey();
	string IV = AES.CreateStringIV();

	//Creates an object
	TestUser user = new TestUser()
	{
		Name = "David",
		Age = 99
	};

	//Encrypts the user object into a string
	string encryptedString = AES.EncryptToString(user, key, IV);

	//Decrypts the it back into a user object
	TestUser decryptedObject = AES.DecryptToType<TestUser>(encryptedString, key, IV);
}
```


### SaveDecryptedFile
This function decrypts the supplied encryption string or byte array and saves it to a specified location.

Syntax
```C#
bool SaveDecryptedFile(string path, byte[] fileData, object key, object IV)
```

Example Usage
```C#
//Generates a key and IV for the example
string key = AES.CreateStringKey();
string IV = AES.CreateStringIV();

//Loads the encrypted files data
byte[] encryptedFile = File.ReadAllBytes($@"C:\1.jpg");

//Saves the loaded encrypted data into a decrypted file
bool decryptedCheck = AES.SaveDecryptedFile($@"C:\1_decrypted.jpg", encryptedFile, key, IV);
```


### LoadDecryptedFile
This function loads an encrypted file from the specified location, decrypts it and then returns the data for it.

Syntax
```C#
byte[] LoadDecryptedFile(string path, object key, object IV)
```

Example Usage
```C#
//Generates a key and IV for the example
string key = AES.CreateStringKey();
string IV = AES.CreateStringIV();

//Loads the encrypted data and decrypts it into a byte array
byte[] decryptedCheck = AES.LoadDecryptedFile($@"C:\1_encrypted.jpg", key, IV);
```




## DataTable Extension Functions

**NOTE: All DataTable encryption extension functions populate the iv column with a randomly generated IV per row.**

the following DataTable will be used in all examples below.
```C#
DataTable dt = new DataTable()
{
	Columns =
	{
		"column_one","column_two", "column_three", "column_four", "column_five", "column_iv",
	},
	Rows =
	{
		{ "one", "two", "three", "four", "five" },
		{ "one2", "two2", "three2", "four2", "five2" },
		{ "3one", "t3wo", "three3", "four3", "five3" },
		{ 2, 3, 4, 5, 6 },
		{ DateTime.Now, 2, 3 },
	}
};
```


### AESEncrypt
This function encrypts all the columns in a DataTable except the IV column

Syntax
```C#
DataTable AESEncrypt(this DataTable data, string ivColumnName, object key)
```

Example Usage
```C#
//Generates a key for the example
string key = AES.CreateStringKey();

//Encrypts the DataTable and returns it
dt = dt.AESEncrypt("column_iv", key);
```


### AESEncryptIgnore
This function encrypts all the columns in a DataTable except the IV column and all column names in the ignore list.

Syntax
```C#
DataTable AESEncryptIgnore(this DataTable data, string ivColumnName, object key, params string[] ignoreColumns)
```

Example Usage
```C#
//Generates a key for the example
string key = AES.CreateStringKey();

//Encrypts the DataTable and returns it
dt = dt.AESEncryptIgnore("column_iv", key, "column_two");
```


### AESEncryptOnly
This function encrypts only the specified columns in a DataTable using the IV column.

Syntax
```C#
DataTable AESEncryptOnly(this DataTable data, string ivColumnName, object key, params string[] onlyColumns)
```

Example Usage
```C#
//Generates a key for the example
string key = AES.CreateStringKey();

//Encrypts the DataTable and returns it
dt = dt.AESEncryptOnly("column_iv", key, "column_two");
```





### AESDecrypt
This function decrypts all the columns in a DataTable except the IV column

Syntax
```C#
DataTable AESDecrypt(this DataTable data, string ivColumnName, object key)
```

Example Usage
```C#
//Generates a key for the example
string key = AES.CreateStringKey();

//Decrypts the DataTable and returns it
dt = dt.AESDecrypt("column_iv", key);
```


### AESDecryptIgnore
This function decrypts all the columns in a DataTable except the iv column and all column names in the ignore list.

Syntax
```C#
DataTable AESDecryptIgnore(this DataTable data, string ivColumnName, object key, params string[] ignoreColumns)
```

Example Usage
```C#
//Generates a key for the example
string key = AES.CreateStringKey();

//Decrypts the DataTable and returns it
dt = dt.AESDecryptIgnore("column_iv", key, "column_two");
```


### AESDecryptOnly
This function decrypts only the specified columns in a DataTable using the IV column.

Syntax
```C#
DataTable AESDecryptOnly(this DataTable data, string ivColumnName, object key, params string[] onlyColumns)
```

Example Usage
```C#
//Generates a key for the example
string key = AES.CreateStringKey();

//Decrypts the DataTable and returns it
dt = dt.AESDecryptOnly("column_iv", key, "column_two");
```


## Copyright and License
Copyright &copy; 2017 David Whitehead

This project is licensed under the MIT License.

You do not have to do anything special by using the MIT license and you don't have to notify anyone that your using this license. You are free to use, modify and distribute this software in any normal and commercial usage. If being used for any commercial purposes the latest copyright license file supplied above which is known as "LICENSE" must also be distributed with any compiled code that is being sold that utilises dotnetaes.

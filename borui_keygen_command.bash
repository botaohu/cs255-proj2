keytool -genkeypair -dname "CN=Very Secure Software, OU=Very Secure Software Group, O=Very Secure Inc, L=Cupertino, 
S=California, C=US" -alias mykey -keypass foobar -keystore ./keystore -storepass foobar -validity 365 -keyalg RSA

# -list -alias mykey -keystore ./keystore -v
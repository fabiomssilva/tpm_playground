# tpm_playground
This is a Trusted Platform Module Playground with some useful code. 


a.For the emulated enviroment please execute tpmd -f (this is the emulator running on foreground)
b.create the device with modprobe tpmd_dev
c.run tcsd -f
f. Maybe a tpm_clear and take ownershipt with defailt password is necessary dont forget default passwors are necessary -y and -z flag :)


1.Have a working TPM with default password 20x"0".
2.use createBindingKeys to create first binding keys for the first time
3.use bindData to encrypt the data on AES.key
4.Use unbunData to get the original data back
5.Use unregisterBiondingKey to unregister the key
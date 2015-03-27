#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tspi.h>
#include <trousers/trousers.h>


#define DEBUG 0
#define DBG(message, tResult) printf("Line%d, %s)%s returned 0x%08x. %s.\n",__LINE__,__func__,message, tResult,(char *)Trspi_Error_String(tResult))
#define BACKUP_KEY_UUID {0,0,0,0,0,{0,0,0,2,10}}
int main(int argc,char **argv)
{
TSS_HCONTEXT hContext;
TSS_HTPM hTPM;
TSS_RESULT result;
TSS_HKEY hSRK=0;
TSS_HPOLICY hSRKPolicy=0;
TSS_UUID SRK_UUID=TSS_UUID_SRK;
BYTE wks[20]; //For the well known secret
// Set wks to the well known secret: 20 bytes of all 0’s
memset(wks,0,20);



//Pick the TPM you are talking to.
// In this case, it is the system TPM (indicated with NULL).
result = Tspi_Context_Create( &hContext);
DBG("Create Context",result);
result = Tspi_Context_Connect(hContext, NULL);
DBG("Context Connect�",result);
// Get the TPM handle
result=Tspi_Context_GetTpmObject(hContext,&hTPM);
DBG("Get TPM Handle",result);

// Get the SRK handle
result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,SRK_UUID,&hSRK);
DBG("Got the SRK handle�", result);
//Get the SRK policy
result = Tspi_GetPolicyObject(hSRK,TSS_POLICY_USAGE,&hSRKPolicy);
DBG("Got the SRK policy",result);
//Then set the SRK policy to be the well known secret
result=Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_SHA1,20,wks);

//Note: TSS SECRET MODE SHA1 says ”Don’t hash this.
// Use the 20 bytes as they are.
DBG("Set the SRK secret in its policy",result);

//Do something usefull





TSS_HKEY hBackup_Key;
TSS_UUID MY_UUID=BACKUP_KEY_UUID;
TSS_HPOLICY hBackup_Policy;
TSS_FLAG initFlags;
BYTE *pubKey;
BYTE pass123[3];
UINT32 pubKeySize;
FILE *fout;
memset(pass123,0,3);

// Create a policy for the new key. Set its password to “123”
result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_POLICY,TSS_POLICY_USAGE, &hBackup_Policy);
DBG("Create a backup policy object",result);

result=Tspi_Policy_SetSecret(hBackup_Policy,TSS_SECRET_MODE_PLAIN,3,pass123);
DBG("Set backup policy object secret",result);

initFlags = TSS_KEY_TYPE_BIND |TSS_KEY_SIZE_2048 |TSS_KEY_AUTHORIZATION |TSS_KEY_NOT_MIGRATABLE;
result=Tspi_Context_CreateObject( hContext,TSS_OBJECT_TYPE_RSAKEY,initFlags, &hBackup_Key );
DBG("Create the key object", result);

// Set the padding type
result = Tspi_SetAttribUint32(hBackup_Key,TSS_TSPATTRIB_KEY_INFO,TSS_TSPATTRIB_KEYINFO_ENCSCHEME,TSS_ES_RSAESPKCSV15);
DBG("Set the keys padding type", result);

// Assign the key’s policy to the key object

result=Tspi_Policy_AssignToObject( hBackup_Policy,hBackup_Key);
DBG("Assign the keys policy to the key", result);


// Create the key, with the SRK as its parent.
printf("Creating the key could take a while\n");
result=Tspi_Key_CreateKey(hBackup_Key,hSRK, 0);
DBG("Asking TPM to create the key", result);


// Once created, I register the key blob so I can retrieve it later
result=Tspi_Context_RegisterKey(hContext,hBackup_Key,TSS_PS_TYPE_SYSTEM,MY_UUID,TSS_PS_TYPE_SYSTEM,SRK_UUID);
DBG("Register the key for later retrieval", result);

printf("Registering key blob for later retrieval\r\n");
result=Tspi_Key_LoadKey(hBackup_Key,hSRK);

DBG("Load key in TPM", result);
result=Tspi_Key_GetPubKey(hBackup_Key,&pubKeySize, &pubKey);

DBG("Get public portion of key", result);
// 2) Save it in a file. The file name will be
// ”BackupESSBindKey.pub”
fout=fopen( "data/BackupESSBindKey.pub", "wb");
if( fout != NULL)
{
write(fileno(fout),pubKey,pubKeySize);
printf("Finished writing BackupESSBindKey.pub\n");
fclose(fout);
}
else
{
printf("Error opening BackupESSBindKey.pub \r\n");
}
// CLEAN UP
Tspi_Policy_FlushSecret(hBackup_Policy);









//Done doing something usefull

// Context Close(hobjects you have created);
Tspi_Context_FreeMemory(hContext,NULL);
// This frees up memory automatically allocated for you.
Tspi_Context_Close(hContext);
return 0;
}



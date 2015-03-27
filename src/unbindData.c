#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
// Set wks to the well known secret: 20 bytes of all 0‚Äôs
memset(wks,0,20);



//Pick the TPM you are talking to.
// In this case, it is the system TPM (indicated with NULL).
result = Tspi_Context_Create( &hContext);
DBG("Create Context",result);
result = Tspi_Context_Connect(hContext, NULL);
DBG("Context Connect‚",result);
// Get the TPM handle
result=Tspi_Context_GetTpmObject(hContext,&hTPM);
DBG("Get TPM Handle",result);
// Get the SRK handle
result=Tspi_Context_LoadKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,SRK_UUID,&hSRK);
DBG("Got the SRK handle‚", result);
//Get the SRK policy
result = Tspi_GetPolicyObject(hSRK,TSS_POLICY_USAGE,&hSRKPolicy);
DBG("Got the SRK policy",result);
//Then set the SRK policy to be the well known secret
result=Tspi_Policy_SetSecret(hSRKPolicy,TSS_SECRET_MODE_SHA1,20,wks);

//Note: TSS SECRET MODE SHA1 says ‚ÄùDon‚Äôt hash this.
// Use the 20 bytes as they are.
DBG("Set the SRK secret in its policy",result);

//Do something usefull

UINT32 ulDataLength;
TSS_HKEY hESS_Bind_Key;
FILE * fin;
FILE * fout;
TSS_HENCDATA hEncData;
TSS_UUID MY_UUID=BACKUP_KEY_UUID;
BYTE encryptedData[256];
BYTE * decryptedData;
BYTE pass123[3];

memset(pass123,0,3);
//Read in the encrypted data from the file
fin=fopen("data/AES.key.enc","rb");
read(fileno(fin),encryptedData,ulDataLength);
fclose(fin);


// Create a data object , fill it with clear text and then bind it.
result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_ENCDATA,TSS_ENCDATA_BIND,&hEncData);
DBG("Create Data object",result);

result = Tspi_Context_GetKeyByUUID(hContext,TSS_PS_TYPE_SYSTEM,MY_UUID,&hESS_Bind_Key);
DBG("Get unbinding key",result);

result = Tspi_Key_LoadKey(hESS_Bind_Key,hSRK);

DBG("Loaded Key",result);


TSS_HPOLICY hBackup_Policy;
// Create a policy for the new key. Set its password to ?~@~\123?~@~]
result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_POLICY,TSS_POLICY_USAGE, &hBackup_Policy);
DBG("Create a backup policy object",result);

result=Tspi_Policy_SetSecret(hBackup_Policy,TSS_SECRET_MODE_PLAIN,3,pass123);
DBG("Set backup policy object secret",result);

// Assign the key?~@~Ys policy to the key object

result=Tspi_Policy_AssignToObject( hBackup_Policy,hESS_Bind_Key);
DBG("Assign the keys policy to the key", result);





result = Tspi_SetAttribData(hEncData,TSS_TSPATTRIB_ENCDATA_BLOB,TSS_TSPATTRIB_ENCDATABLOB_BLOB,256,encryptedData);
DBG("Load Data",result);

// Use the Unbinding key to decrypt the encrypted data
// in the BindData object, and return it
result=Tspi_Data_Unbind(hEncData,hESS_Bind_Key,&ulDataLength,&decryptedData);
DBG("Unbind",result);

fout=fopen("data/originalAES.key", "wb");
write(fileno(fout),decryptedData,ulDataLength);
fclose(fout);

//Done doing something usefull

// Context Close(hobjects you have created);
Tspi_Context_FreeMemory(hContext,NULL);
// This frees up memory automatically allocated for you.
Tspi_Context_Close(hContext);
return 0;
}


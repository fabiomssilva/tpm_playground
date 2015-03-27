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
BYTE *rgbBoundData;
TSS_HKEY hESS_Bind_Key;
FILE * fin;
FILE * fout;
TSS_FLAG initFlags;
BYTE encData[7];
BYTE newPubKey[284];
TSS_HENCDATA hEncData;

initFlags = TSS_KEY_TYPE_BIND |TSS_KEY_SIZE_2048 |TSS_KEY_AUTHORIZATION |TSS_KEY_NOT_MIGRATABLE;

// Retrieve the public key
fin =fopen("data/BackupESSBindKey.pub", "r");
read(fileno(fin),newPubKey,284);
fclose(fin);


// Create a key object
result=Tspi_Context_CreateObject( hContext,TSS_OBJECT_TYPE_RSAKEY,initFlags, &hESS_Bind_Key );
DBG("Tspi Context CreateObject BindKey",result);

// Feed the key object with the public key read from the file
result=Tspi_SetAttribData(hESS_Bind_Key,TSS_TSPATTRIB_KEY_BLOB,TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,284, newPubKey);
DBG("Set Public key into new key object", result);


// Read in the data to be encrypted
fin=fopen("data/AES.key","rb");
read(fileno(fin),encData,7);
fclose(fin);

// Create a data object , fill it with clear text and then bind it.
result=Tspi_Context_CreateObject(hContext,TSS_OBJECT_TYPE_ENCDATA,TSS_ENCDATA_BIND,&hEncData);
DBG("Create Data object",result);

result=Tspi_Data_Bind( hEncData,hESS_Bind_Key,7,encData);
DBG("Bind data",result);


// Get the encrypted data out of the data object
result=Tspi_GetAttribData( hEncData,TSS_TSPATTRIB_ENCDATA_BLOB,TSS_TSPATTRIB_ENCDATABLOB_BLOB,&ulDataLength,&rgbBoundData);

DBG("Get encrypted data", result);
// Write the encrypted data out to a file called Bound.data

fout=fopen("data/AES.key.enc", "wb");
write(fileno(fout),rgbBoundData,ulDataLength);
fclose(fout);


//Done doing something usefull

// Context Close(hobjects you have created);
Tspi_Context_FreeMemory(hContext,NULL);
// This frees up memory automatically allocated for you.
Tspi_Context_Close(hContext);
return 0;
}


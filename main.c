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

TSS_HKEY hKey=0;
BYTE some_data_buf[7] = {0,1,2,3,4,5,6};
BYTE * bind_data_buf;
UINT32 bind_data_size;


BYTE * unbind_data_buf;
UINT32 unbind_data_size;


TSS_HENCDATA hEncData;

// create key
TSS_FLAG initFlags = TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048 |TSS_KEY_VOLATILE | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_NOT_MIGRATABLE;
result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hKey);
DBG("",result);
result = Tspi_Key_CreateKey(hKey, hSRK, 0);
DBG("",result);
result = Tspi_Key_LoadKey(hKey, hSRK);
DBG("",result);
//bind some data
result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA,TSS_ENCDATA_LEGACY, &hEncData); //also tried TSS_ENCDATA_BIND
DBG("",result);
result = Tspi_Data_Bind(hEncData, hKey,7 , some_data_buf);
DBG("",result);
result = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,TSS_TSPATTRIB_ENCDATABLOB_BLOB, &bind_data_size, &bind_data_buf);
DBG("Set the SRK secret in its policy",result);
//try to unbind data
TSS_HENCDATA hAnotherData;
Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_ENCDATA, TSS_ENCDATA_LEGACY, &hAnotherData); //also tried TSS_ENCDATA_BIND
DBG("Set the SRK secret in its policy",result);
result = Tspi_SetAttribData(hAnotherData, TSS_TSPATTRIB_ENCDATA_BLOB,TSS_TSPATTRIB_ENCDATABLOB_BLOB, bind_data_size, bind_data_buf);
DBG("Set the SRK secret in its policy",result);
result = Tspi_Data_Unbind(hAnotherData, hKey, &unbind_data_size, &unbind_data_buf);
DBG("Set the SRK secret in its policy",result);
// Got error here: 0x21 (Decryption error)



//Done doing something usefull

// Context Close(hobjects you have created);
Tspi_Context_FreeMemory(hContext,NULL);
// This frees up memory automatically allocated for you.
Tspi_Context_Close(hContext);
return 0;
}



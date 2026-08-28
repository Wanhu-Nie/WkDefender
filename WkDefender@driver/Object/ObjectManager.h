#pragma once
#include "../Common/Constants.h"

NTSTATUS InitializeObjectManager();
NTSTATUS RegisterObjectCallback();
OB_PREOP_CALLBACK_STATUS OnObjectPreOperation(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
VOID OnObjectPostOperation(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation);

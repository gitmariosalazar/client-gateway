// src/settings/environments/environments.ts
import 'dotenv/config';
import * as joi from 'joi';

interface EnvironmentsVariables {
  PORT: number;
  AUTH_MICROSERVICE_PORT: number;
  AUTH_MICROSERVICE_HOST: string;
  AUTH_SERVICE: string;
  NOTIFICATION_MICROSERVICE_PORT: number;
  NOTIFICATION_MICROSERVICE_HOST: string;
  NOTIFICATION_SERVICE: string;
  DOCUMENTS_MICROSERVICE_PORT: number;
  DOCUMENTS_MICROSERVICE_HOST: string;
  DOCUMENTS_SERVICE: string;
  JWT_SECRET_KEY?: string;
  KAFKA_BROKER: string;
  AUTHENTICATION_KAFKA_CLIENT: string;
  DOCUMENTS_KAFKA_CLIENT: string;
  NOTIFICATION_KAFKA_CLIENT: string;
  AUTHENTICATION_KAFKA_GROUP_ID: string;
  DOCUMENTS_KAFKA_GROUP_ID: string;
  NOTIFICATION_KAFKA_GROUP_ID: string;
  AUTHENTICATION_KAFKA_CLIENT_ID: string;
  DOCUMENTS_KAFKA_CLIENT_ID: string;
  NOTIFICATION_KAFKA_CLIENT_ID: string;
  DOCUMENTS_DOCUMENT_GROUP_ID: string;
  DOCUMENTS_ENTERPRISE_GROUP_ID: string;
  DOCUMENTS_DETAIL_INVOICE_GROUP_ID: string;
  DOCUMENTS_PROCESS_GROUP_ID: string;
  DOCUMENTS_PROCESS_DOCUMENT_GROUP_ID: string;
  DOCUMENTS_PROCESS_REVIEW_GROUP_ID: string;
  DOCUMENTS_SERVICES_GROUP_ID: string;
  DOCUMENTS_STATUS_GROUP_ID: string;
  DOCUMENTS_DOCUMENT_TYPE_GROUP_ID: string;
  DOCUMENTS_TYPE_PAYMENT_GROUP_ID: string;
  DOCUMENTS_TYPE_SERVICE_GROUP_ID: string;
  DOCUMENTS_TYPE_STATUS_GROUP_ID: string;
  NOTIFICATION_NOTIFICATION_GROUP_ID: string;
  NOTIFICATION_PRIORITY_GROUP_ID: string;
  NOTIFICATION_TYPE_NOTIFICATION_GROUP_ID: string;
  AUTH_USER_GROUP_ID: string;
  AUTH_ROLE_GROUP_ID: string;
  AUTH_PERMISSION_GROUP_ID: string;
  AUTH_USER_TYPE_GROUP_ID: string;
  AUTH_SECURITY_GROUP_ID: string;
}

const environmentsSchema = joi
  .object({
    PORT: joi.number().required(),
    AUTH_MICROSERVICE_PORT: joi.number(),
    AUTH_MICROSERVICE_HOST: joi.string(),
    AUTH_SERVICE: joi.string(),
    NOTIFICATION_MICROSERVICE_PORT: joi.number(),
    NOTIFICATION_MICROSERVICE_HOST: joi.string(),
    NOTIFICATION_SERVICE: joi.string(),
    DOCUMENTS_MICROSERVICE_PORT: joi.number(),
    DOCUMENTS_MICROSERVICE_HOST: joi.string(),
    DOCUMENTS_SERVICE: joi.string(),
    JWT_SECRET_KEY: joi.string(),
    KAFKA_BROKER: joi.string().required(),
    AUTHENTICATION_KAFKA_CLIENT: joi.string(),
    DOCUMENTS_KAFKA_CLIENT: joi.string(),
    NOTIFICATION_KAFKA_CLIENT: joi.string(),
    AUTHENTICATION_KAFKA_GROUP_ID: joi.string(),
    NOTIFICATION_KAFKA_GROUP_ID: joi.string(),
    AUTHENTICATION_KAFKA_CLIENT_ID: joi.string(),
    DOCUMENTS_KAFKA_CLIENT_ID: joi.string(),
    NOTIFICATION_KAFKA_CLIENT_ID: joi.string(),
    DOCUMENTS_DOCUMENT_GROUP_ID: joi.string(),
    DOCUMENTS_ENTERPRISE_GROUP_ID: joi.string(),
    DOCUMENTS_DETAIL_INVOICE_GROUP_ID: joi.string(),
    DOCUMENTS_PROCESS_GROUP_ID: joi.string(),
    DOCUMENTS_PROCESS_DOCUMENT_GROUP_ID: joi.string(),
    DOCUMENTS_PROCESS_REVIEW_GROUP_ID: joi.string(),
    DOCUMENTS_SERVICES_GROUP_ID: joi.string(),
    DOCUMENTS_STATUS_GROUP_ID: joi.string(),
    DOCUMENTS_DOCUMENT_TYPE_GROUP_ID: joi.string(),
    DOCUMENTS_TYPE_PAYMENT_GROUP_ID: joi.string(),
    DOCUMENTS_TYPE_SERVICE_GROUP_ID: joi.string(),
    DOCUMENTS_TYPE_STATUS_GROUP_ID: joi.string(),
    NOTIFICATION_NOTIFICATION_GROUP_ID: joi.string(),
    NOTIFICATION_PRIORITY_GROUP_ID: joi.string(),
    NOTIFICATION_TYPE_NOTIFICATION_GROUP_ID: joi.string(),
    AUTH_USER_GROUP_ID: joi.string(),
    AUTH_ROLE_GROUP_ID: joi.string(),
    AUTH_PERMISSION_GROUP_ID: joi.string(),
    AUTH_USER_TYPE_GROUP_ID: joi.string(),
    AUTH_SECURITY_GROUP_ID: joi.string(),
  })
  .unknown(true);

const { error, value } = environmentsSchema.validate(process.env);
if (error) {
  throw new Error(`Configuration error: ${error.message}`);
}

const environmentsVariables: EnvironmentsVariables = value;

export const environments = {
  serverPort: environmentsVariables.PORT,
  authMicroservicePort: environmentsVariables.AUTH_MICROSERVICE_PORT,
  authMicroserviceHost: environmentsVariables.AUTH_MICROSERVICE_HOST,
  authService: environmentsVariables.AUTH_SERVICE,
  notificationMicroservicePort:
    environmentsVariables.NOTIFICATION_MICROSERVICE_PORT,
  notificationMicroserviceHost:
    environmentsVariables.NOTIFICATION_MICROSERVICE_HOST,
  notificationService: environmentsVariables.NOTIFICATION_SERVICE,
  documentsMicroservicePort: environmentsVariables.DOCUMENTS_MICROSERVICE_PORT,
  documentsMicroserviceHost: environmentsVariables.DOCUMENTS_MICROSERVICE_HOST,
  documentsService: environmentsVariables.DOCUMENTS_SERVICE,
  jwtSecretKey: environmentsVariables.JWT_SECRET_KEY,
  kafkaBroker: environmentsVariables.KAFKA_BROKER,
  authenticationKafkaClient: environmentsVariables.AUTHENTICATION_KAFKA_CLIENT,
  documentsKafkaClient: environmentsVariables.DOCUMENTS_KAFKA_CLIENT,
  notificationKafkaClient: environmentsVariables.NOTIFICATION_KAFKA_CLIENT,
  authenticationKafkaGroupId:
    environmentsVariables.AUTHENTICATION_KAFKA_GROUP_ID,
  documentsKafkaGroupId: environmentsVariables.DOCUMENTS_KAFKA_GROUP_ID,
  notificationKafkaGroupId: environmentsVariables.NOTIFICATION_KAFKA_GROUP_ID,
  authenticationKafkaClientId:
    environmentsVariables.AUTHENTICATION_KAFKA_CLIENT_ID,
  documentsKafkaClientId: environmentsVariables.DOCUMENTS_KAFKA_CLIENT_ID,
  notificationKafkaClientId: environmentsVariables.NOTIFICATION_KAFKA_CLIENT_ID,
  isDevelopment: process.env.NODE_ENV !== 'production',
  isProduction: process.env.NODE_ENV === 'production',
  isTest: process.env.NODE_ENV === 'test',
  isStaging: process.env.NODE_ENV === 'staging',
  isLocal: process.env.NODE_ENV === 'local',
  isDocker: process.env.NODE_ENV === 'docker',
  isKubernetes: process.env.NODE_ENV === 'kubernetes',
  documentsDocumentGroupId: environmentsVariables.DOCUMENTS_DOCUMENT_GROUP_ID,
  documentsEnterpriseGroupId:
    environmentsVariables.DOCUMENTS_ENTERPRISE_GROUP_ID,
  documentsDetailInvoiceGroupId:
    environmentsVariables.DOCUMENTS_DETAIL_INVOICE_GROUP_ID,
  documentsProcessGroupId: environmentsVariables.DOCUMENTS_PROCESS_GROUP_ID,
  documentsProcessDocumentGroupId:
    environmentsVariables.DOCUMENTS_PROCESS_DOCUMENT_GROUP_ID,
  documentsProcessReviewGroupId:
    environmentsVariables.DOCUMENTS_PROCESS_REVIEW_GROUP_ID,
  documentsServicesGroupId: environmentsVariables.DOCUMENTS_SERVICES_GROUP_ID,
  documentsStatusGroupId: environmentsVariables.DOCUMENTS_STATUS_GROUP_ID,
  documentsDocumentTypeGroupId:
    environmentsVariables.DOCUMENTS_DOCUMENT_TYPE_GROUP_ID,
  documentsTypePaymentGroupId:
    environmentsVariables.DOCUMENTS_TYPE_PAYMENT_GROUP_ID,
  documentsTypeServiceGroupId:
    environmentsVariables.DOCUMENTS_TYPE_SERVICE_GROUP_ID,
  documentsTypeStatusGroupId:
    environmentsVariables.DOCUMENTS_TYPE_STATUS_GROUP_ID,
  notificationNotificationGroupId:
    environmentsVariables.NOTIFICATION_NOTIFICATION_GROUP_ID,
  notificationPriorityGroupId:
    environmentsVariables.NOTIFICATION_PRIORITY_GROUP_ID,
  notificationTypeNotificationGroupId:
    environmentsVariables.NOTIFICATION_TYPE_NOTIFICATION_GROUP_ID,
  authUserGroupId: environmentsVariables.AUTH_USER_GROUP_ID,
  authRoleGroupId: environmentsVariables.AUTH_ROLE_GROUP_ID,
  authPermissionGroupId: environmentsVariables.AUTH_PERMISSION_GROUP_ID,
  authUserTypeGroupId: environmentsVariables.AUTH_USER_TYPE_GROUP_ID,
  authSecurityGroupId: environmentsVariables.AUTH_SECURITY_GROUP_ID,
};

import { Module } from '@nestjs/common';
import { HomeModule } from './app/module/app.module';
import { UserTypeGatewayModule } from './services/authentication/modules/user-type/infrastructure/module/user-type.gateway.module';
import { UserGatewayModule } from './services/authentication/modules/users/infrastructure/module/user.gateway.module';
import { PermissionGatewayModule } from './services/authentication/modules/permission/infrastructure/modules/permission.gateway.module';
import { RolePermissionGatewayModule } from './services/authentication/modules/roles/infrastructure/module/role-permission.gateway.module';
import { AuthGatewayModule } from './services/authentication/modules/security/infrastructure/module/auth.gateway.module';
import { JwtModule } from '@nestjs/jwt';
import { environments } from './settings/environments/environments';
import { AuthGuard } from './auth/guard/auth.guard';
import { TypeStatusGatewayModule } from './services/docs/modules/type-status/infrastructure/module/type-status.gateway.module';
import { TypeServicesGatewayModule } from './services/docs/modules/type-services/infrastructure/module/type-services.gateway.module';
import { TypeDocumentsGatewayModule } from './services/docs/modules/type-documents/infrastructure/module/type-documents.gateway.module';
import { TypePaymentGatewayModule } from './services/docs/modules/type-payments/infrastructure/module/type-payment.gateway.module';
import { StatusGatewayModule } from './services/docs/modules/status/infrastructure/module/status.gateway.module';
import { ServicesGatewayModule } from './services/docs/modules/services/infrastructure/module/services.gateway.module';
import { EntityGatewayModule } from './services/docs/modules/enterprise/infrastructure/module/entity.gateway.module';
import { ProcessGatewayModule } from './services/docs/modules/process/infrastructure/module/process.gateway.module';
import { ProcessReviewGatewayModule } from './services/docs/modules/process-review/infrastructure/module/process-review.gateway.module';
import { DocumentsGatewayModule } from './services/docs/modules/documents/infrastructure/module/documents.gateway.module';
import { ProcessDocumentGatewayModule } from './services/docs/modules/process-docs/infrastructure/module/process-document.gateway.module';
import { DetailInvoiceGatewayModule } from './services/docs/modules/invoices/infrastructure/module/detail-invoice.gateway.module';
import { TypeNotificationGatewayModule } from './services/notifications/modules/type-notification/infrastructure/module/type-notification.gateway.module';
import { PriorityGatewayModule } from './services/notifications/modules/priority/infrastructure/module/priority.gateway.module';
import { NotificationGatewayModule } from './services/notifications/modules/notifications/infrastructure/module/notification.gateway.module';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { NotificationKafkaModule } from './shared/kafka/notifications.kafka.module';
import { DocumentsKafkaModule } from './shared/kafka/documents.kafka.module';
import { AuthenticationKafkaModule } from './shared/kafka/authentication.kafka.module';

@Module({
  imports: [
    HomeModule,
    NotificationKafkaModule,
    DocumentsKafkaModule,
    AuthenticationKafkaModule,
    UserTypeGatewayModule,
    UserGatewayModule,
    PermissionGatewayModule,
    RolePermissionGatewayModule,
    AuthGatewayModule,
    TypeStatusGatewayModule,
    TypeServicesGatewayModule,
    TypeDocumentsGatewayModule,
    TypePaymentGatewayModule,
    StatusGatewayModule,
    ServicesGatewayModule,
    EntityGatewayModule,
    ProcessGatewayModule,
    ProcessReviewGatewayModule,
    DocumentsGatewayModule,
    ProcessDocumentGatewayModule,
    DetailInvoiceGatewayModule,
    TypeNotificationGatewayModule,
    PriorityGatewayModule,
    NotificationGatewayModule,
    JwtModule.register({
      global: true,
      secret: environments.jwtSecretKey,
      signOptions: { expiresIn: '1h', algorithm: 'HS256' },
    }),
  ],
  controllers: [],
  providers: [AuthGuard],
  exports: [AuthGuard],
})
export class AppModule {}

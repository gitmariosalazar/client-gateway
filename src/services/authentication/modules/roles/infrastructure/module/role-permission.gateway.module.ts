import { Module } from '@nestjs/common';
import { RolePermissionGatewayController } from '../controller/role-permission.gateway.controller';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';

@Module({
  imports: [
    ClientsModule.register([
      {
        name: environments.authenticationKafkaClient!,
        transport: Transport.KAFKA,
        options: {
          client: {
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.authRoleGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [RolePermissionGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class RolePermissionGatewayModule {}

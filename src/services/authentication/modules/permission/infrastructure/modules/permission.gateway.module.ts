import { Module } from '@nestjs/common';
import { PermissionGatewayController } from '../controller/permission.gateway.controller';
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
            groupId: environments.authPermissionGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [PermissionGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class PermissionGatewayModule {}

import { Module } from '@nestjs/common';
import { TypeNotificationGatewayController } from '../controller/type-notification.gateway.controller';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';

@Module({
  imports: [
    ClientsModule.register([
      {
        name: environments.notificationKafkaClient!,
        transport: Transport.KAFKA,
        options: {
          client: {
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.notificationTypeNotificationGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [TypeNotificationGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class TypeNotificationGatewayModule {}

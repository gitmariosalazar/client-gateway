import { Module } from '@nestjs/common';
import { NotificationGatewayController } from '../controller/notification.gateway.controller';
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
            groupId: environments.notificationNotificationGroupId,
            sessionTimeout: 30000, // Tiempo en ms antes de que el broker considere al consumidor desconectado
            heartbeatInterval: 10000, // Intervalo en ms para enviar heartbeats
            rebalanceTimeout: 60000,
          },
        },
      },
    ]),
  ],
  controllers: [NotificationGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class NotificationGatewayModule {}

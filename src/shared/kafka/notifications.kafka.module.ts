import { Module } from '@nestjs/common';
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
            clientId: environments.notificationKafkaClientId!,
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.notificationKafkaGroupId!,
          },
        },
      },
    ]),
  ],
  exports: [ClientsModule],
})
export class NotificationKafkaModule {}

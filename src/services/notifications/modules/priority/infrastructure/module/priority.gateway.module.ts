import { Module } from '@nestjs/common';
import { PriorityGatewayController } from '../controller/priority.gateway.controller';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';
import { NotificationKafkaModule } from 'src/shared/kafka/notifications.kafka.module';

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
            groupId: environments.notificationPriorityGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [PriorityGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class PriorityGatewayModule {}

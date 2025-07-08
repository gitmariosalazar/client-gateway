import { Module } from '@nestjs/common';
import { ServicesGatewayController } from '../controller/services.gateway.controller';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';

@Module({
  imports: [
    ClientsModule.register([
      {
        name: environments.documentsKafkaClient!,
        transport: Transport.KAFKA,
        options: {
          client: {
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.documentsServicesGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [ServicesGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class ServicesGatewayModule {}

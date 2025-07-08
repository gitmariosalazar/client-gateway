import { Module } from '@nestjs/common';
import { ProcessGatewayController } from '../controller/process.gateway.controller';
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
            groupId: environments.documentsProcessGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [ProcessGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class ProcessGatewayModule {}

import { Module } from '@nestjs/common';
import { StatusGatewayController } from '../controller/status.gateway.controller';
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
            groupId: environments.documentsStatusGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [StatusGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class StatusGatewayModule {}

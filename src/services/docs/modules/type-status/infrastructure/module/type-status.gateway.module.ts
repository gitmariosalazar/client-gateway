import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';
import { TypeStatusGatewayController } from '../controller/type-status.gateway.controller';

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
            groupId: environments.documentsTypeStatusGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [TypeStatusGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class TypeStatusGatewayModule {}

import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';
import { TypeServicesGatewayController } from '../controller/type-services.gateway.controller';

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
            groupId: environments.documentsTypeServiceGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [TypeServicesGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class TypeServicesGatewayModule {}

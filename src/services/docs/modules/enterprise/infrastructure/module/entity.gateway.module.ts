import { Module } from '@nestjs/common';
import { EntityGatewayController } from '../controller/entity.gateway.controller';
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
            groupId: environments.documentsEnterpriseGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [EntityGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class EntityGatewayModule {}

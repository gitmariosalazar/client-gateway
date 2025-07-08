import { Module } from '@nestjs/common';
import { TypePaymentGatewayController } from '../controller/type-payment.gateway.controller';
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
            groupId: environments.documentsTypePaymentGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [TypePaymentGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class TypePaymentGatewayModule {}

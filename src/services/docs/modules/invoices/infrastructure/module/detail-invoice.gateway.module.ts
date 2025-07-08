import { Module } from '@nestjs/common';
import { DetailInvoiceGatewayController } from '../controller/detail-invoice.gateway.controller';
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
            groupId: environments.documentsDetailInvoiceGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [DetailInvoiceGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class DetailInvoiceGatewayModule {}

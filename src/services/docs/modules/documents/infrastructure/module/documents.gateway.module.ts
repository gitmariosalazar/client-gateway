import { Module } from '@nestjs/common';
import { DocumentsGatewayController } from '../controller/documents.gateway.controller';
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
            groupId: environments.documentsDocumentGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [DocumentsGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class DocumentsGatewayModule {}

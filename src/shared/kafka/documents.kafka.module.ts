import { Module } from '@nestjs/common';
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
            clientId: environments.documentsKafkaClientId!,
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.documentsKafkaGroupId!,
          },
        },
      },
    ]),
  ],
  exports: [ClientsModule],
})
export class DocumentsKafkaModule {}

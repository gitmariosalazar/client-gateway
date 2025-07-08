import { Module } from '@nestjs/common';
import { ProcessReviewGatewayController } from '../controller/process-review.gateway.controller';
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
            groupId: environments.documentsProcessReviewGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [ProcessReviewGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class ProcessReviewGatewayModule {}

"use client";

import { Button, Card } from "@heroui/react";
import { useEffect } from "react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm">
        <Card.Content className="p-8 text-center">
          <h1 className="mb-2 text-2xl font-bold text-foreground">
            Сервис временно недоступен
          </h1>
          <p className="mb-6 text-sm text-muted">
            Не удалось загрузить страницу. Обновите её или вернитесь позже. Если
            ошибка повторяется — проверьте конфигурацию сервиса входа.
          </p>
          <Button variant="outline" fullWidth onPress={reset}>
            Обновить
          </Button>
        </Card.Content>
      </Card>
    </div>
  );
}

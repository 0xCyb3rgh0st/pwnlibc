.PHONY: build test lint run doctor clean

build:
	docker compose build cli

test:
	docker compose run --rm test

lint:
	docker compose run --rm lint

doctor:
	docker compose run --rm cli doctor

clean:
	docker compose down -v

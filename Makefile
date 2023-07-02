images:
	docker build -f ./docker/Dockerfile -t tgtg-scanner:latest .
	docker build -f ./docker/Dockerfile.alpine -t tgtg-scanner:latest-alpine .

install:
	poetry install

start:
	poetry run scanner -d

executable:
	rm -r ./build ||:
	rm -r ./dist ||:
	poetry run pyinstaller ./scanner.spec
	cp ./src/config.sample.ini ./dist/config.ini
	zip -j ./dist/scanner.zip ./dist/*

test:
	poetry run pytest -v -m "not tgtg_api" --cov src/

lint:
	poetry run pre-commit run -a

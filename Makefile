SWIFT := ./Scripts/swift.sh

.PHONY: build release test dependency-check clean

build:
	$(SWIFT) build

release:
	$(SWIFT) build -c release
	./Scripts/sign.sh .build/release/cengine

test: dependency-check
	$(SWIFT) test

dependency-check:
	./Scripts/check-dependencies.sh

clean:
	$(SWIFT) package clean

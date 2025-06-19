
.PHONY: build clean

build:
	@javac -nowarn -source 1.7 -target 1.7 \
	  *.java
	
	@dx --dex --output=classes.dex \
	  *.class

clean:
	$(RM) *.class *.dex *.zip

##########################################
# Barplot Analysis of the NSL-KDD Data set
##########################################
library(ggplot2)
library(plotly)
library(data.table)
library(dplyr)
library(RColorBrewer)
library(devtools)
library(curl)


######
# Data

#train_full <- "KDDTrain+.txt"
#train <- "KDDTrain+_20Percent.txt"
#test <- "KDDTest+.txt"

#train <- fread(train, header = FALSE,skip=1)

#test <- fread(test, header = FALSE)



######
# Plot

## Bar Plot of connection types in set


bars <- function(){
  ## Categories Bar Plot
  dat1 <- data.frame(
    sets = factor(c("Training Set", "Test Set", 
                    "Training Set", "Test Set", 
                    "Training Set", "Test Set",
                    "Training Set", "Test Set", 
                    "Training Set", "Test Set")),
    categories = factor(c("DoS", "probe", "r2l", "u2r", "normal",
                           "DoS", "probe", "r2l", "u2r", "normal"), levels=c("DoS", "probe", "r2l", "u2r", "normal")),
    counts = c(9234, 2289, 209, 11, 13449,7167, 2421, 2885, 67, 9711)
  )
  
  # Bar graph, time on x-axis, color fill grouped by sex -- use position_dodge()
  p <- ggplot(data=dat1, aes(x=categories, y=counts, fill=sets)) +
    geom_bar(stat="identity", position=position_dodge()) +
    ggtitle("Network Class Distribution of NSL-KDD Train (20%) and Test Data Set")
  print(p)
}

#----------------------------------------------------------------------
#########
# Heatmap
#########

## Categorize the Data
categorize <- function(data){
  #--------#
  # normal
  #--------#
  ids_normal <- filter(data, V42 == "normal")
  normal <- rep("normal", nrow(ids_normal))
  ids_normal <- cbind(ids_normal, normal)
  
  #-----#
  # DOS 
  #-----#
  ids_DOS <- filter(data, V42 == "back" | V42 == "land" | V42 == "neptune" | V42 == "pod" 
                    | V42 == "smurf" | V42 == "teardrop" | V42 == "apache2" | V42 == "udpstorm"
                    | V42 == "processtable" | V42 == "worm")
  DOS <- rep("DOS", nrow(ids_DOS))
  ids_DOS <- cbind(ids_DOS,DOS)
  
  #------#
  # Probe
  #------#
  ids_probe <- filter(data, V42 == "satan" | V42 == "ipsweep" | V42 == "nmap" 
                      | V42 == "portsweep" | V42 == "mscan" | V42 == "saint")
  probe <- rep("probe", nrow(ids_probe))
  ids_probe <- cbind(ids_probe, probe)
  #-----#
  # r2l
  #-----#
  ids_r2l <- filter(data, V42 == "guess_passwd" | V42 == "ftp_write" | V42 == "imap" 
                    | V42 == "phf" | V42 == "multihop" | V42 == "warezmaster"
                    | V42 == "warezclient" | V42 == "spy" | V42 == "xlock" | V42 == "xsnoop"
                    | V42 == "snmpguess" | V42 == "snmpgetattack" | V42 == "httptunnel"
                    | V42 == "sendmail" | V42 == "named")
  r2l <- rep("r2l", nrow(ids_r2l))
  ids_r2l <- cbind(ids_r2l, r2l)
  #-----#
  # u2r
  #-----#
  ids_u2r <- filter(data, V42 == "buffer_overflow" | V42 == "loadmodule" | V42 == "rootkit"
                    | V42 == "perl" | V42 == "sqlattack" | V42 == "xterm" | V42 == "ps")
  u2r <- rep("u2r", nrow(ids_u2r))
  ids_u2r <- cbind(ids_u2r, u2r)
  #---------#
  # unknown
  #---------#
  ids_unknown <- filter(data, V42 != "normal" & V42 != "back" & V42 != "land" 
                        & V42 != "neptune" & V42 != "pod" & V42 != "smurf" & V42 != "teardrop"
                        & V42 == "apache2" & V42 == "udpstorm" & V42 == "processtable" & V42 == "worm"
                        & V42 != "satan" & V42 != "ipsweep" & V42 != "nmap" & V42 != "portsweep"
                        & V42 == "mscan" & V42 == "saint"
                        & V42 != "guess_passwd" & V42 != "ftp_write" & V42 != "imap" 
                        & V42 != "phf" & V42 != "multihop" & V42 != "warezmaster" 
                        & V42 != "warezclient" & V42 != "spy"  
                        & V42 == "xlock" & V42 == "xsnoop" & V42 == "snmpguess" & V42 == "snmpgetattack" & V42 == "httptunnel"
                        & V42 == "sendmail" & V42 == "named" & V42 != "buffer_overflow" 
                        & V42 != "loadmodule" & V42 != "rootkit"
                        & V42 == "perl" & V42 == "sqlattack" & V42 == "xterm" & V42 == "ps")
  unknown <- rep("unknown", nrow(ids_unknown))
  ids_unknown <- cbind(ids_unknown, unknown)
  
  #--------------------------------------------#
  # Label the columns in each new data frame
  #--------------------------------------------#
  colnames(ids_DOS)[ncol(ids_DOS)] <- "V44"
  colnames(ids_probe)[ncol(ids_probe)] <- "V44"
  colnames(ids_u2r)[ncol(ids_u2r)] <- "V44"
  colnames(ids_r2l)[ncol(ids_r2l)] <- "V44"
  colnames(ids_normal)[ncol(ids_normal)] <- "V44"
  colnames(ids_unknown)[ncol(ids_unknown)] <- "V44"
  
  data <- rbind(ids_DOS, ids_probe, ids_r2l, ids_u2r, ids_normal, ids_unknown)
  
  result <- list(Categorized_Data = data)
  return(result)
}


  
## Heatmap of attacks vs. connection type

## attacks vs. V2 (protocol_type)
heat <- function(testdata){
test <- categorize(testdata)$Categorized_Data

counts <- as.data.frame(table(test$V2, test$V44))
colnames(counts) <- c("sets", "categories", "Frequency")

h <- ggplot(counts, aes(x = categories, y = sets))+
  geom_raster(aes(fill = Frequency))+
  labs(title ="Heat Map", x = "Category Type", y = "Connection Type")+
  scale_fill_continuous(name = "Count") 
print(h)
}

## attacks vs. V3 (service)
heat2 <- function(testdata){
  test <- categorize(testdata)$Categorized_Data
  
  counts <- as.data.frame(table(test$V3, test$V44))
  colnames(counts) <- c("sets", "categories", "Frequency")

  ggplot(counts, aes(x = categories, y = sets))+
    geom_raster(aes(fill = Frequency))+
    labs(title ="Heat Map", x = "Category Type", y = "Service")+
    scale_fill_continuous(name = "Count") 
}

## attacks vs. v4 (flag)
heat3 <- function(testdata){
  test <- categorize(testdata)$Categorized_Data
  
  counts <- as.data.frame(table(test$V4, test$V44))
  colnames(counts) <- c("sets", "categories", "Frequency")
  
  ggplot(counts, aes(x = categories, y = sets))+
    geom_raster(aes(fill = Frequency))+
    labs(title ="Heat Map", x = "Category Type", y = "Flags")+
    scale_fill_continuous(name = "Count") 
}
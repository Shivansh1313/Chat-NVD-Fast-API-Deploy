import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import openai
from openai import OpenAI
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

class Chatbot:
    def __init__(self, file_paths, api_key):
        self.file_paths = file_paths
        openai.api_key = api_key
        self.knowledge_base = self.load_data()
        self.documents = self.prepare_documents()
        self.vectorizer = TfidfVectorizer()
        self.tfidf_matrix = self.vectorizer.fit_transform(self.documents)
        self.full_documents = self.knowledge_base
        self.cve_index = self.create_cve_index()
        self.conversation_history = []

    def load_data(self):
        all_data = []
        for file_path in self.file_paths:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                all_data.extend(data)
        return all_data

    def concatenate_text(self, json_obj):
        fields = ['CVE_ID', 'Assigner', 'Description']
        concatenated_text = ' '.join(str(json_obj[field]) for field in fields if field in json_obj)
        return concatenated_text

    def prepare_documents(self):
        return [self.concatenate_text(item) for item in self.knowledge_base]

    def create_cve_index(self):
        cve_index = {}
        for idx, item in enumerate(self.knowledge_base):
            cve_id = item.get('CVE_ID')
            if cve_id:
                cve_index[cve_id] = idx
        return cve_index

    def answer_question(self, query):
        query_words = query.split()
        found_documents = []

        # Check if any word in the query is a CVE_ID
        for word in query_words:
            if word in self.cve_index:
                index = self.cve_index[word]
                found_documents.append(self.full_documents[index])

        # If any CVE_ID is found, return the corresponding documents
        if found_documents:
            return found_documents

        # If no CVE_ID is found, proceed with TF-IDF similarity search
        similarity_scores = np.zeros(len(self.documents))

        for word in query_words:
            query_vec = self.vectorizer.transform([word])
            similarities = cosine_similarity(query_vec, self.tfidf_matrix)[0]
            similarity_scores += similarities

        top_indices = np.argsort(similarity_scores)[-10:][::-1]
        top_documents = [self.full_documents[i] for i in top_indices]
        return top_documents

    def get_response(self, question):
        self.conversation_history.append({"role": "user", "content": question})

        # Get answers from knowledge base
        answers = self.answer_question(question)
        json_string = json.dumps(answers, indent=4)
        messages = [
            {"role": "system", "content": "You are an assistant that helps with CVE data. Respond with relevant CVE details. Only answer from the context"}
        ] + [
            {"role": "assistant", "content": json_string}
        ] + self.conversation_history

        try:
            client = OpenAI()
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=messages
            )
            response = completion.choices[0].message.content
            self.conversation_history.append({"role": "assistant", "content": response})
            return response

        except openai.error.RateLimitError:
            raise HTTPException(status_code=429, detail="API rate limit exceeded. Please try again later.")
        except openai.error.OpenAIError as e:
            raise HTTPException(status_code=500, detail=f"An API error occurred: {e}")
        except openai.error.AuthenticationError:
            raise HTTPException(status_code=401, detail="Authentication failed. Check your API key.")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

# Initialize the chatbot with multiple files
file_paths = [
    'data/nvdcve-1.1-recent_updated.json',
    'data/nvdcve-1.1-modified_updated.json',
    'data/nvdcve-1.1-2024_updated.json',
    'data/nvdcve-1.1-2023_updated.json',
    'data/nvdcve-1.1-2022_updated.json',
    'data/nvdcve-1.1-2021_updated.json',
    'data/nvdcve-1.1-2020_updated.json',
    'data/nvdcve-1.1-2019_updated.json',
    'data/nvdcve-1.1-2018_updated.json',
    'data/nvdcve-1.1-2017_updated.json',
    'data/nvdcve-1.1-2016_updated.json',
    'data/nvdcve-1.1-2015_updated.json',
    'data/nvdcve-1.1-2014_updated.json',
    'data/nvdcve-1.1-2013_updated.json',
    'data/nvdcve-1.1-2012_updated.json',
    'data/nvdcve-1.1-2011_updated.json',
    'data/nvdcve-1.1-2010_updated.json',
    'data/nvdcve-1.1-2009_updated.json',
    'data/nvdcve-1.1-2008_updated.json',
    'data/nvdcve-1.1-2007_updated.json',
    'data/nvdcve-1.1-2006_updated.json',
    'data/nvdcve-1.1-2005_updated.json',
    'data/nvdcve-1.1-2004_updated.json',
    'data/nvdcve-1.1-2003_updated.json',
    'data/nvdcve-1.1-2002_updated.json'
]
api_key = 'your-api-key'
chatbot = Chatbot(file_paths, api_key)

# Define the FastAPI app
app = FastAPI()

# Define the request model
class Question(BaseModel):
    question: str

# Define the endpoint
@app.post("/ask")
def ask_question(question: Question):
    response = chatbot.get_response(question.question)
    return {"answer": response}

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000)

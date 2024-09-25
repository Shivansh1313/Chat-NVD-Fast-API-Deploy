# in this UI is changed in to a window This working latest on 19th Sep 2024
import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import openai
import tkinter as tk
from tkinter import scrolledtext
from openai import OpenAI


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
        self.setup_interface()

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

    def should_use_previous_context(self, question):
        client = OpenAI()
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Determine if the following question is a follow-up question."},
                {"role": "user", "content": question}
            ]
        )
        response = completion.choices[0].message.content.strip().lower()
        return 'yes' in response

    def handle_question(self):
        question = self.text_input.get()
        self.conversation_history.append({"role": "user", "content": question})

        # if self.should_use_previous_context(question):
        #     messages = [
        #         {"role": "system", "content": "You are an assistant that helps with CVE data. Respond with relevant CVE details. Use previous context as well"}
        #     ] + self.conversation_history
        if(True):
            answers = self.answer_question(question)
            json_string = json.dumps(answers, indent=4)
            messages = [
                {"role": "system", "content": "You are an assistant that helps with CVE data. Respond with relevant CVE details. Only answer from the context"}
            ]  + [
                {"role": "assistant", "content": json_string}
            ]+ self.conversation_history

        self.display_message(f'Question: {question}', 'blue')
        for message in messages:
            print(message)

        try:
            client = OpenAI()
            completion = client.chat.completions.create(
                #model="gpt-3.5-turbo",
                #model="gpt-4o",
                model="gpt-4o-mini",
                messages=messages
            )
            response = completion.choices[0].message.content
            self.conversation_history.append({"role": "assistant", "content": response})
            self.display_message(f'Answer:\n{response}', 'green')

        # except openai.error.RateLimitError:
        #     self.display_message("API rate limit exceeded. Please try again later.", 'red')
        # except openai.error.OpenAIError as e:
        #     self.display_message(f"An API error occurred: {e}", 'red')
        # except openai.error.AuthenticationError:
        #     self.display_message("Authentication failed. Check your API key.", 'red')
        except Exception as e:
            self.display_message(f"An unexpected error occurred: {e}", 'red')

    def display_message(self, message, color):
        self.results_output.configure(state='normal')
        self.results_output.insert(tk.END, message + '\n', (color,))
        self.results_output.configure(state='disabled')
        self.results_output.see(tk.END)

    def setup_interface(self):
        root = tk.Tk()
        root.title("Chatbot Interface")

        self.text_input = tk.Entry(root, width=100)
        self.text_input.pack(pady=10)
        self.text_input.bind('<Return>', lambda event: self.handle_question())

        self.results_output = scrolledtext.ScrolledText(root, width=100, height=30, wrap=tk.WORD)
        self.results_output.pack(pady=10)
        self.results_output.tag_configure('blue', foreground='blue')
        self.results_output.tag_configure('green', foreground='green')
        self.results_output.tag_configure('red', foreground='red')
        self.results_output.configure(state='disabled')

        root.mainloop()

# Initialize the chatbot with multiple files
file_paths = [
    'nvdcve-1.1-recent_updated.json',
    'nvdcve-1.1-modified_updated.json',
    'nvdcve-1.1-2024_updated.json',
 'nvdcve-1.1-2023_updated.json',
 'nvdcve-1.1-2022_updated.json',
 'nvdcve-1.1-2021_updated.json',
 'nvdcve-1.1-2020_updated.json',
 'nvdcve-1.1-2019_updated.json',
 'nvdcve-1.1-2018_updated.json',
 'nvdcve-1.1-2017_updated.json',
 'nvdcve-1.1-2016_updated.json',
 'nvdcve-1.1-2015_updated.json',
 'nvdcve-1.1-2014_updated.json',
 'nvdcve-1.1-2013_updated.json',
 'nvdcve-1.1-2012_updated.json',
 'nvdcve-1.1-2011_updated.json',
 'nvdcve-1.1-2010_updated.json',
 'nvdcve-1.1-2009_updated.json',
 'nvdcve-1.1-2008_updated.json',
 'nvdcve-1.1-2007_updated.json',
 'nvdcve-1.1-2006_updated.json',
 'nvdcve-1.1-2005_updated.json',
 'nvdcve-1.1-2004_updated.json',
 'nvdcve-1.1-2003_updated.json',
 'nvdcve-1.1-2002_updated.json'
]
api_key = 'your-api-key'
chatbot = Chatbot(file_paths, api_key)
